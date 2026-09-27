// server.js
const express = require('express');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const { Server } = require('socket.io');
const {
  hashIp,
  getClientIp,
  isBanned,
  applyBan,
  unban,
  canReport,
  fileReport
} = require('./lib/moderation');

const app = express();

// Render sits behind a reverse proxy — this makes req.ip / X-Forwarded-For
// resolve to the real visitor IP instead of Render's internal proxy IP.
app.set('trust proxy', true);
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// Admin panel auth — email + password login (env vars only, never hardcode
// real credentials in this file). Set on Render:
//   ADMIN_EMAIL=you@example.com
//   ADMIN_PASSWORD=some-strong-password
// On successful login we hand back an httpOnly session cookie; every
// /admin/api/* route checks that cookie against the in-memory session store.
// ---------------------------------------------------------------------------
const db = require('./lib/db');

const sessions = new Map(); // token -> expiresAt
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

const failedLogins = new Map(); // ip -> { count, lockedUntil }
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

function parseCookies(req) {
  const header = req.headers.cookie;
  const out = {};
  if (!header) return out;
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return out;
}

function timingSafeStringEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function requireAdmin(req, res, next) {
  const cookies = parseCookies(req);
  const token = cookies.admin_session;
  const expiresAt = token && sessions.get(token);
  if (!token || !expiresAt || expiresAt < Date.now()) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin', 'admin.html'));
});

app.post('/admin/login', (req, res) => {
  const ip = getClientIp({ handshake: { headers: req.headers, address: req.socket.remoteAddress } });
  const lock = failedLogins.get(ip);
  if (lock && lock.lockedUntil && lock.lockedUntil > Date.now()) {
    return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  }

  const { email, password } = req.body || {};
  const expectedEmail = process.env.ADMIN_EMAIL || '';
  const expectedPassword = process.env.ADMIN_PASSWORD || '';

  const ok = expectedEmail && expectedPassword &&
    timingSafeStringEqual(email || '', expectedEmail) &&
    timingSafeStringEqual(password || '', expectedPassword);

  if (!ok) {
    const entry = failedLogins.get(ip) || { count: 0, lockedUntil: 0 };
    entry.count += 1;
    if (entry.count >= MAX_ATTEMPTS) {
      entry.lockedUntil = Date.now() + LOCKOUT_MS;
      entry.count = 0;
    }
    failedLogins.set(ip, entry);
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  failedLogins.delete(ip);
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, Date.now() + SESSION_TTL_MS);
  res.setHeader('Set-Cookie', `admin_session=${token}; HttpOnly; Path=/; Max-Age=${SESSION_TTL_MS / 1000}; SameSite=Strict`);
  res.json({ ok: true });
});

app.post('/admin/logout', (req, res) => {
  const cookies = parseCookies(req);
  if (cookies.admin_session) sessions.delete(cookies.admin_session);
  res.setHeader('Set-Cookie', 'admin_session=; HttpOnly; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.get('/admin/api/reports', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT * FROM reports ORDER BY created_at DESC LIMIT 300').all();
  res.json(rows);
});

app.get('/admin/api/bans', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT * FROM bans ORDER BY banned_at DESC').all();
  res.json(rows);
});

app.post('/admin/api/ban', requireAdmin, (req, res) => {
  const { ipHash, reason } = req.body || {};
  if (!ipHash) return res.status(400).json({ error: 'ipHash required' });
  const result = applyBan(ipHash, reason || 'Manual ban by admin');
  res.json({ ok: true, result });
});

app.post('/admin/api/unban', requireAdmin, (req, res) => {
  const { ipHash } = req.body || {};
  if (!ipHash) return res.status(400).json({ error: 'ipHash required' });
  unban(ipHash);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Matching + signaling
// ---------------------------------------------------------------------------
let waitingQueue = [];       // { id: socket.id, country }
const partners = new Map();  // socket.id -> partner socket.id
const socketIpHash = new Map(); // socket.id -> hashed IP (for reports/bans)

function broadcastActiveUsers() {
  io.emit('active-users', io.sockets.sockets.size);
}

function isCompatible(a, b) {
  return a.country === 'ANY' || b.country === 'ANY' || a.country === b.country;
}

function tryMatch() {
  waitingQueue = waitingQueue.filter((entry) => io.sockets.sockets.has(entry.id));

  for (let i = 0; i < waitingQueue.length; i++) {
    const entry = waitingQueue[i];
    const matchIdx = waitingQueue.findIndex(
      (other, j) => j !== i && isCompatible(entry, other)
    );

    if (matchIdx !== -1) {
      const other = waitingQueue[matchIdx];
      waitingQueue = waitingQueue.filter((e) => e.id !== entry.id && e.id !== other.id);

      partners.set(entry.id, other.id);
      partners.set(other.id, entry.id);

      io.to(entry.id).emit('matched', { peerId: other.id, initiator: true });
      io.to(other.id).emit('matched', { peerId: entry.id, initiator: false });

      tryMatch();
      return;
    }
  }
}

function disconnectPartner(socketId, reason) {
  const partnerId = partners.get(socketId);
  if (partnerId) {
    io.to(partnerId).emit('partner-left', { reason });
    partners.delete(partnerId);
  }
  partners.delete(socketId);
}

// Force-ends whatever call `targetSocketId` is in and kicks it back to idle,
// used when that user gets auto-banned mid-call.
function forceEndAndNotifyBanned(targetSocketId, banResult) {
  disconnectPartner(targetSocketId, 'moderation');
  waitingQueue = waitingQueue.filter((e) => e.id !== targetSocketId);
  io.to(targetSocketId).emit('banned', {
    reason: banResult.reason || 'Violation detected',
    expiresAt: banResult.expiresAt,
    permanent: banResult.permanent
  });
  const sock = io.sockets.sockets.get(targetSocketId);
  if (sock) sock.disconnect(true);
}

io.on('connection', (socket) => {
  const ip = getClientIp(socket);
  const ipHash = hashIp(ip);
  socketIpHash.set(socket.id, ipHash);

  const existingBan = isBanned(ipHash);
  if (existingBan) {
    socket.emit('banned', {
      reason: existingBan.reason,
      expiresAt: existingBan.expires_at,
      permanent: !existingBan.expires_at
    });
    socket.disconnect(true);
    return;
  }

  console.log('connected:', socket.id);
  broadcastActiveUsers();

  socket.on('find-peer', (payload = {}) => {
    if (isBanned(ipHash)) { socket.disconnect(true); return; }
    const country = typeof payload.country === 'string' && payload.country ? payload.country : 'ANY';
    disconnectPartner(socket.id, 'requeued');
    waitingQueue = waitingQueue.filter((e) => e.id !== socket.id);
    waitingQueue.push({ id: socket.id, country });
    tryMatch();
  });

  socket.on('leave', () => {
    disconnectPartner(socket.id, 'left');
    waitingQueue = waitingQueue.filter((e) => e.id !== socket.id);
  });

  socket.on('offer', ({ target, offer }) => {
    io.to(target).emit('offer', { from: socket.id, offer });
  });

  socket.on('answer', ({ target, answer }) => {
    io.to(target).emit('answer', { from: socket.id, answer });
  });

  socket.on('ice-candidate', ({ target, candidate }) => {
    io.to(target).emit('ice-candidate', { from: socket.id, candidate });
  });

  socket.on('chat-message', ({ target, text }) => {
    io.to(target).emit('chat-message', { from: socket.id, text });
  });

  // Manual "Report" button — the only reporting path for now (AI auto-flagging removed).
  socket.on('report-user', ({ target }) => {
    const reporterHash = ipHash;
    const reportedHash = socketIpHash.get(target);
    if (!reportedHash) return;

    if (!canReport(reporterHash)) {
      io.to(socket.id).emit('report-received', { throttled: true });
      return;
    }

    console.log(`[REPORT] ${socket.id} reported ${target} at ${new Date().toISOString()}`);
    const banResult = fileReport({ reporterHash, reportedHash, reason: 'user-report', source: 'user' });
    io.to(socket.id).emit('report-received', { throttled: false });
    disconnectPartner(socket.id, 'reported');

    if (banResult) forceEndAndNotifyBanned(target, banResult);
  });

  socket.on('disconnect', () => {
    console.log('disconnected:', socket.id);
    disconnectPartner(socket.id, 'disconnected');
    waitingQueue = waitingQueue.filter((e) => e.id !== socket.id);
    socketIpHash.delete(socket.id);
    broadcastActiveUsers();
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

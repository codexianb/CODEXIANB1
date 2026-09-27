// lib/moderation.js
// Core anti-abuse logic: identifies users anonymously by a salted hash of
// their IP (there are no accounts in this app), tracks reports against that
// hash, and auto-bans once enough distinct people report the same person
// within a time window. Bans escalate: 24h -> 7 days -> permanent.
const crypto = require('crypto');
const db = require('./db');

const IP_SALT = process.env.IP_SALT || 'change-this-in-render-env-vars';
const REPORT_WINDOW_MS = 24 * 60 * 60 * 1000; // count reports from the last 24h
const REPORT_THRESHOLD = 3;                    // distinct reporters before auto-ban
const REPORT_COOLDOWN_MS = 15 * 1000;          // a reporter can't spam the report button

const lastReportAt = new Map(); // reporterHash -> timestamp (in-memory rate limit only)

function hashIp(ip) {
  return crypto.createHash('sha256').update(`${IP_SALT}|${ip}`).digest('hex');
}

function getClientIp(socket) {
  // Render sits behind a proxy, so the real visitor IP is in X-Forwarded-For.
  const forwarded = socket.handshake.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return socket.handshake.address;
}

function isBanned(ipHash) {
  const row = db.prepare('SELECT * FROM bans WHERE ip_hash = ?').get(ipHash);
  if (!row) return null;
  if (row.expires_at && row.expires_at < Date.now()) {
    db.prepare('DELETE FROM bans WHERE ip_hash = ?').run(ipHash);
    return null;
  }
  return row;
}

function banDurationForStrike(strikeCount) {
  if (strikeCount === 1) return 24 * 60 * 60 * 1000;      // 24 hours
  if (strikeCount === 2) return 7 * 24 * 60 * 60 * 1000;  // 7 days
  return null; // 3rd strike onward = permanent
}

function applyBan(ipHash, reason) {
  const existing = db.prepare('SELECT strike_count FROM bans WHERE ip_hash = ?').get(ipHash);
  const strikeCount = (existing?.strike_count || 0) + 1;
  const duration = banDurationForStrike(strikeCount);
  const now = Date.now();

  db.prepare(`
    INSERT INTO bans (ip_hash, reason, strike_count, banned_at, expires_at)
    VALUES (@ip_hash, @reason, @strike_count, @banned_at, @expires_at)
    ON CONFLICT(ip_hash) DO UPDATE SET
      reason = excluded.reason,
      strike_count = excluded.strike_count,
      banned_at = excluded.banned_at,
      expires_at = excluded.expires_at
  `).run({
    ip_hash: ipHash,
    reason,
    strike_count: strikeCount,
    banned_at: now,
    expires_at: duration ? now + duration : null
  });

  return { strikeCount, expiresAt: duration ? now + duration : null, permanent: !duration, reason };
}

function unban(ipHash) {
  db.prepare('DELETE FROM bans WHERE ip_hash = ?').run(ipHash);
}

function canReport(reporterHash) {
  const last = lastReportAt.get(reporterHash) || 0;
  if (Date.now() - last < REPORT_COOLDOWN_MS) return false;
  lastReportAt.set(reporterHash, Date.now());
  return true;
}

// source: 'user' (manual report button) or 'ai' (nudity-detection flag)
function fileReport({ reporterHash, reportedHash, reason, source = 'user' }) {
  db.prepare(`
    INSERT INTO reports (reporter_hash, reported_hash, reason, source, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(reporterHash, reportedHash, reason || null, source, Date.now());

  const windowStart = Date.now() - REPORT_WINDOW_MS;
  const { count } = db.prepare(`
    SELECT COUNT(DISTINCT reporter_hash) as count FROM reports
    WHERE reported_hash = ? AND created_at >= ?
  `).get(reportedHash, windowStart);

  if (count >= REPORT_THRESHOLD) {
    return applyBan(reportedHash, `Auto-ban: ${count} distinct reports within 24h`);
  }
  return null;
}

module.exports = {
  hashIp,
  getClientIp,
  isBanned,
  applyBan,
  unban,
  canReport,
  fileReport,
  REPORT_THRESHOLD
};

// server.js
const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.static(path.join(__dirname, 'public')));

// Each waiting entry: { id: socket.id, country: 'ANY' | 'PH' | 'US' | ... }
let waitingQueue = [];
const partners = new Map();

function broadcastActiveUsers() {
  io.emit('active-users', io.sockets.sockets.size);
}

function isCompatible(a, b) {
  return a.country === 'ANY' || b.country === 'ANY' || a.country === b.country;
}

function tryMatch() {
  // Drop any entries whose socket has since disconnected.
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

      tryMatch(); // keep matching whoever is left
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

io.on('connection', (socket) => {
  console.log('connected:', socket.id);
  broadcastActiveUsers();

  socket.on('find-peer', (payload = {}) => {
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

  socket.on('report-user', ({ target }) => {
    console.log(`[REPORT] ${socket.id} reported ${target} at ${new Date().toISOString()}`);
    io.to(socket.id).emit('report-received');
    disconnectPartner(socket.id, 'reported');
  });

  socket.on('disconnect', () => {
    console.log('disconnected:', socket.id);
    disconnectPartner(socket.id, 'disconnected');
    waitingQueue = waitingQueue.filter((e) => e.id !== socket.id);
    broadcastActiveUsers();
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

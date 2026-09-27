// lib/db.js
// Persistent storage for reports and bans, backed by SQLite (file on disk).
// NOTE: on Render's free tier the filesystem is ephemeral across deploys —
// for production durability, mount a persistent disk (Render "Disks" add-on)
// at this path, or swap this file for a hosted DB (Postgres/Mongo) later.
// Everything else in the app talks to this file through the functions in
// lib/moderation.js, so swapping the backend only means rewriting this file.
const path = require('path');
const Database = require('better-sqlite3');

const dbPath = process.env.DB_PATH || path.join(__dirname, '..', 'moderation.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_hash TEXT NOT NULL,
    reported_hash TEXT NOT NULL,
    reason TEXT,
    source TEXT NOT NULL DEFAULT 'user',
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS bans (
    ip_hash TEXT PRIMARY KEY,
    reason TEXT,
    strike_count INTEGER NOT NULL DEFAULT 1,
    banned_at INTEGER NOT NULL,
    expires_at INTEGER
  );

  CREATE INDEX IF NOT EXISTS idx_reports_reported ON reports(reported_hash, created_at);
  CREATE INDEX IF NOT EXISTS idx_reports_reporter ON reports(reporter_hash, created_at);
`);

module.exports = db;

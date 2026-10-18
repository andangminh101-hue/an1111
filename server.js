const express = require('express');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Server } = require('socket.io');

const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error('Set SESSION_SECRET to a random string of at least 32 characters in .env');
  process.exit(1);
}
if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12 || ADMIN_PASSWORD === 'change-this-admin-password') {
  console.error('Set ADMIN_PASSWORD to a unique password of at least 12 characters in .env');
  process.exit(1);
}

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const fs = require('fs');
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'game.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS players (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  gold INTEGER NOT NULL DEFAULT 100,
  xp INTEGER NOT NULL DEFAULT 0,
  level INTEGER NOT NULL DEFAULT 1,
  wins INTEGER NOT NULL DEFAULT 0,
  score INTEGER NOT NULL DEFAULT 0,
  banned INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
  sid TEXT PRIMARY KEY,
  sess TEXT NOT NULL,
  expired TEXT NOT NULL
);
`);
const q = {
  byName: db.prepare('SELECT * FROM players WHERE username = ?'),
  byId: db.prepare('SELECT id, username, gold, xp, level, wins, score, banned, created_at FROM players WHERE id = ?'),
  insert: db.prepare('INSERT INTO players (username, password_hash) VALUES (?, ?)'),
  leaderboard: db.prepare('SELECT username, level, wins, score FROM players WHERE banned = 0 ORDER BY score DESC, wins DESC, level DESC LIMIT 50'),
  players: db.prepare('SELECT id, username, gold, xp, level, wins, score, banned, created_at FROM players ORDER BY created_at DESC LIMIT 200'),
  ban: db.prepare('UPDATE players SET banned = ? WHERE id = ?'),
  updateStats: db.prepare('UPDATE players SET gold = ?, xp = ?, level = ?, wins = ?, score = ? WHERE id = ?')
};

const sessionMiddleware = session({
  store: new SQLiteStore({ db: 'sessions.db', dir: DATA_DIR }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb' }));
app.use(sessionMiddleware);
io.engine.use(sessionMiddleware);
app.use('/api/', rateLimit({ windowMs: 60_000, limit: 100, standardHeaders: true, legacyHeaders: false }));
app.use(express.static(path.join(__dirname, 'public')));

function currentPlayer(req) {
  if (!req.session.playerId) return null;
  return q.byId.get(req.session.playerId);
}
function requirePlayer(req, res, next) {
  const player = currentPlayer(req);
  if (!player) return res.status(401).json({ error: 'Vui lòng đăng nhập.' });
  if (player.banned) {
    req.session.destroy(() => {});
    return res.status(403).json({ error: 'Tài khoản đã bị khóa.' });
  }
  req.player = player;
  next();
}
function requireAdmin(req, res, next) {
  if (req.session.isAdmin !== true) return res.status(401).json({ error: 'Cần đăng nhập quản trị.' });
  next();
}

app.get('/api/health', (req, res) => res.json({ ok: true, game: 'Gold Tower Defense Server' }));

app.post('/api/register', async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({ error: 'Tên tài khoản 3–20 ký tự, chỉ gồm chữ, số và dấu gạch dưới.' });
  }
  if (password.length < 8 || password.length > 72) {
    return res.status(400).json({ error: 'Mật khẩu cần từ 8 đến 72 ký tự.' });
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = q.insert.run(username, hash);
    req.session.playerId = Number(result.lastInsertRowid);
    res.json({ player: q.byId.get(req.session.playerId) });
  } catch (e) {
    res.status(409).json({ error: 'Tên tài khoản đã tồn tại hoặc không thể tạo tài khoản.' });
  }
});

app.post('/api/login', async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const player = q.byName.get(username);
  if (!player || !(await bcrypt.compare(password, player.password_hash))) {
    return res.status(401).json({ error: 'Sai tên tài khoản hoặc mật khẩu.' });
  }
  if (player.banned) return res.status(403).json({ error: 'Tài khoản đã bị khóa.' });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Không thể tạo phiên đăng nhập.' });
    req.session.playerId = player.id;
    req.session.save(() => res.json({ player: q.byId.get(player.id) }));
  });
});

app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/me', requirePlayer, (req, res) => res.json({ player: req.player }));
app.get('/api/leaderboard', (req, res) => res.json({ leaderboard: q.leaderboard.all() }));

// Game server must validate match results before calling this route.
// Do not trust client-submitted gold, XP, wins, or score in a production game.
app.post('/api/game/result', requirePlayer, (req, res) => {
  const { won, score } = req.body || {};
  if (typeof won !== 'boolean' || !Number.isInteger(score) || score < 0 || score > 1000000) {
    return res.status(400).json({ error: 'Kết quả trận không hợp lệ.' });
  }
  const p = q.byId.get(req.player.id);
  const xp = p.xp + Math.min(score, 1000);
  const level = Math.floor(xp / 500) + 1;
  const wins = p.wins + (won ? 1 : 0);
  const totalScore = p.score + score;
  const gold = Math.min(p.gold + (won ? 50 : 10), 2000000000);
  q.updateStats.run(gold, xp, level, wins, totalScore, p.id);
  const updated = q.byId.get(p.id);
  io.emit('leaderboard:update', q.leaderboard.all());
  res.json({ player: updated });
});

app.post('/api/admin/login', async (req, res) => {
  const username = String(req.body.username || '');
  const password = String(req.body.password || '');
  const okUser = username === ADMIN_USERNAME;
  // Admin password is compared against environment value; use a timing-safe comparison.
  const a = Buffer.from(password);
  const b = Buffer.from(ADMIN_PASSWORD);
  const okPass = a.length === b.length && crypto.timingSafeEqual(a, b);
  if (!okUser || !okPass) return res.status(401).json({ error: 'Thông tin quản trị không đúng.' });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Không thể tạo phiên quản trị.' });
    req.session.isAdmin = true;
    req.session.save(() => res.json({ ok: true }));
  });
});
app.get('/api/admin/players', requireAdmin, (req, res) => res.json({ players: q.players.all() }));
app.post('/api/admin/players/:id/ban', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const banned = req.body.banned;
  if (!Number.isInteger(id) || typeof banned !== 'boolean') return res.status(400).json({ error: 'Dữ liệu không hợp lệ.' });
  q.ban.run(banned ? 1 : 0, id);
  const player = q.byId.get(id);
  if (!player) return res.status(404).json({ error: 'Không tìm thấy người chơi.' });
  res.json({ player });
});
app.post('/api/admin/logout', requireAdmin, (req, res) => req.session.destroy(() => res.json({ ok: true })));

io.on('connection', socket => {
  socket.emit('leaderboard:update', q.leaderboard.all());
});

app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

server.listen(PORT, () => console.log(`Tower Defense server running at http://localhost:${PORT}`));

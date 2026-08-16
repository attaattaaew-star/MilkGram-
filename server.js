// Milkgram MVP server
// Express (REST API: регистрация/вход/история сообщений) + Socket.io (реальное время) + SQLite (хранение)

const express = require("express");
const http = require("http");
const path = require("path");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const { Server } = require("socket.io");

const JWT_SECRET = process.env.JWT_SECRET || "milkgram-dev-secret-change-me";
const PORT = process.env.PORT || 3000;

const db = new Database(path.join(__dirname, "milkgram.db"));
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_id INTEGER NOT NULL,
    to_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    read INTEGER DEFAULT 0,
    FOREIGN KEY(from_id) REFERENCES users(id),
    FOREIGN KEY(to_id) REFERENCES users(id)
  );
`);

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "Нет токена" });
  const token = header.replace("Bearer ", "");
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;
    req.username = payload.username;
    next();
  } catch {
    return res.status(401).json({ error: "Недействительный токен" });
  }
}

app.post("/api/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || username.length < 3 || password.length < 4) {
    return res.status(400).json({ error: "Логин от 3 символов, пароль от 4 символов" });
  }
  const exists = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
  if (exists) return res.status(409).json({ error: "Такой логин уже занят" });

  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)").run(username, hash);
  const token = jwt.sign({ id: info.lastInsertRowid, username }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, user: { id: info.lastInsertRowid, username } });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: "Неверный логин или пароль" });
  }
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, user: { id: user.id, username: user.username } });
});

app.get("/api/users", authMiddleware, (req, res) => {
  const users = db
    .prepare("SELECT id, username FROM users WHERE id != ? ORDER BY username")
    .all(req.userId);
  res.json(users);
});

app.get("/api/messages/:otherId", authMiddleware, (req, res) => {
  const otherId = Number(req.params.otherId);
  const rows = db
    .prepare(
      `SELECT * FROM messages
       WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)
       ORDER BY id ASC`
    )
    .all(req.userId, otherId, otherId, req.userId);
  db.prepare("UPDATE messages SET read = 1 WHERE from_id = ? AND to_id = ?").run(otherId, req.userId);
  res.json(rows);
});

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

const onlineUsers = new Map();

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    const payload = jwt.verify(token, JWT_SECRET);
    socket.userId = payload.id;
    socket.username = payload.username;
    next();
  } catch {
    next(new Error("Auth error"));
  }
});

io.on("connection", (socket) => {
  onlineUsers.set(socket.userId, socket.id);
  io.emit("presence", { userId: socket.userId, online: true });

  socket.on("private_message", ({ to, text }) => {
    if (!text || !text.trim()) return;
    const info = db
      .prepare("INSERT INTO messages (from_id, to_id, text) VALUES (?, ?, ?)")
      .run(socket.userId, to, text.trim());

    const message = {
      id: info.lastInsertRowid,
      from_id: socket.userId,
      to_id: to,
      text: text.trim(),
      created_at: new Date().toISOString(),
      read: 0,
    };

    socket.emit("new_message", message);
    const targetSocketId = onlineUsers.get(to);
    if (targetSocketId) {
      io.to(targetSocketId).emit("new_message", message);
    }
  });

  socket.on("disconnect", () => {
    onlineUsers.delete(socket.userId);
    io.emit("presence", { userId: socket.userId, online: false });
  });
});

server.listen(PORT, () => {
  console.log(`Milkgram server running on http://localhost:${PORT}`);
});

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET || "CHANGE_ME_IN_PRODUCTION";

if (SESSION_SECRET === "CHANGE_ME_IN_PRODUCTION") {
  console.warn("WARNING: Set SESSION_SECRET before production.");
}

const db = new Database(path.join(__dirname, "sini-ngumpul.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS works (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  title TEXT NOT NULL,
  type TEXT NOT NULL,
  description TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS security_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event TEXT NOT NULL,
  ip TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

const adminEmail = process.env.ADMIN_EMAIL || "admin@sinignumpul.local";
const adminPassword = process.env.ADMIN_PASSWORD || "ChangeMe_123!";
const existingAdmin = db.prepare("SELECT id FROM users WHERE email = ?").get(adminEmail);
if (!existingAdmin) {
  const hash = bcrypt.hashSync(adminPassword, 12);
  db.prepare("INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,?)")
    .run("Admin Sini Ngumpul", adminEmail, hash, "admin");
  console.log(`Initial admin: ${adminEmail}`);
  console.log("Change the default password before production.");
}

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"]
    }
  }
}));
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false, limit: "100kb" }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 8
  }
}));

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: "draft-8",
  legacyHeaders: false
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  message: { error: "Terlalu banyak percobaan. Coba lagi beberapa menit." }
});
const workLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  message: { error: "Pengiriman karya terlalu sering. Coba lagi nanti." }
});
app.use(globalLimiter);

function logSecurity(event, req) {
  try {
    db.prepare("INSERT INTO security_logs (event, ip) VALUES (?,?)")
      .run(event, req.ip || "unknown");
  } catch (_) {}
}

function clean(value, max = 500) {
  return String(value ?? "").trim().replace(/\s+/g, " ").slice(0, max);
}

function validText(value, max = 500) {
  if (!value || value.length > max) return false;
  return !/<\s*script|javascript\s*:|on\w+\s*=|<\s*(iframe|object|embed)/i.test(value);
}

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Login diperlukan." });
  next();
}
function requireModerator(req, res, next) {
  if (!req.session.user || !["admin","moderator"].includes(req.session.user.role))
    return res.status(403).json({ error: "Akses moderator diperlukan." });
  next();
}

app.post("/api/login", authLimiter, (req, res) => {
  const email = clean(req.body.email, 120).toLowerCase();
  const password = String(req.body.password || "");
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    logSecurity("LOGIN_FAILED", req);
    return res.status(401).json({ error: "Email atau password salah." });
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Gagal membuat sesi." });
    req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
    logSecurity("LOGIN_SUCCESS", req);
    res.json({ user: req.session.user });
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", (req, res) => {
  res.json({ user: req.session.user || null });
});

app.post("/api/works", workLimiter, (req, res) => {
  const name = clean(req.body.name, 100);
  const title = clean(req.body.title, 160);
  const type = clean(req.body.type, 80);
  const description = clean(req.body.description, 1000);

  if (![name,title,type,description].every(v => validText(v))) {
    logSecurity("WORK_REJECTED_INPUT", req);
    return res.status(400).json({ error: "Input tidak valid." });
  }

  db.prepare(`INSERT INTO works (name,title,type,description) VALUES (?,?,?,?)`)
    .run(name, title, type, description);
  logSecurity("WORK_SUBMITTED", req);
  res.status(201).json({ ok: true, message: "Karya dikirim dan menunggu moderasi." });
});

app.get("/api/works", (req, res) => {
  const works = db.prepare(
    "SELECT id,name,title,type,description,created_at FROM works WHERE status='approved' ORDER BY id DESC LIMIT 50"
  ).all();
  res.json({ works });
});

app.get("/api/moderation/works", requireModerator, (req, res) => {
  res.json({ works: db.prepare("SELECT * FROM works ORDER BY id DESC LIMIT 100").all() });
});

app.post("/api/moderation/works/:id", requireModerator, (req, res) => {
  const status = ["approved","rejected","pending"].includes(req.body.status) ? req.body.status : null;
  if (!status) return res.status(400).json({ error: "Status tidak valid." });
  db.prepare("UPDATE works SET status=? WHERE id=?").run(status, Number(req.params.id));
  logSecurity(`WORK_${status.toUpperCase()}`, req);
  res.json({ ok: true });
});

app.get("/api/security/logs", requireModerator, (req, res) => {
  res.json({ logs: db.prepare("SELECT * FROM security_logs ORDER BY id DESC LIMIT 100").all() });
});

app.use(express.static(path.join(__dirname, "public")));

app.use((req, res) => {
  res.status(404).json({ error: "Tidak ditemukan." });
});

app.listen(PORT, () => {
  console.log(`Sini Ngumpul berjalan di http://localhost:${PORT}`);
});

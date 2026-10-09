const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static("public"));

const SECRET = "DoiThanhChuoiBiMatCuaBan123";
const DB_FILE = path.join(__dirname, "public", "db.json");
const ADMIN = {
  username: "admin",
  passwordHash: bcrypt.hashSync("admin123", 10)
};

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
    fs.writeFileSync(DB_FILE, JSON.stringify({ keys: [] }));
  }
  try {
    return JSON.parse(fs.readFileSync(DB_FILE));
  } catch (e) {
    return { keys: [] };
  }
}

function saveDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

function auth(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ error: "Chua dang nhap" });
  try {
    jwt.verify(token.replace("Bearer ", ""), SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Token sai" });
  }
}

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (username !== ADMIN.username || !bcrypt.compareSync(password, ADMIN.passwordHash)) {
    return res.status(401).json({ error: "Sai tai khoan" });
  }
  const token = jwt.sign({ username }, SECRET, { expiresIn: "7d" });
  res.json({ token });
});

function durationToMs(type) {
  switch (type) {
    case "1h": return 3600000;
    case "1d": return 86400000;
    case "1w": return 604800000;
    case "1m": return 2592000000;
    case "1y": return 31536000000;
    case "forever": return null;
    default: return null;
  }
}

function randomKey(len = 20) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < len; i++)
    out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

app.post("/api/create-key", auth, (req, res) => {
  const { duration, quantity, maxUses } = req.body;
  const db = loadDB();
  const qty = Math.max(1, Math.min(1000, parseInt(quantity) || 1));
  const max = Math.max(0, parseInt(maxUses) || 0);
  const ms = durationToMs(duration);
  const now = Date.now();

  const created = [];
  for (let i = 0; i < qty; i++) {
    const key = randomKey();
    db.keys.push({
      key,
      duration,
      createdAt: now,
      expiresAt: ms ? now + ms : null,
      maxUses: max,
      usedBy: []
    });
    created.push(key);
  }
  saveDB(db);
  res.json({ success: true, keys: created });
});

app.delete("/api/delete-key/:key", auth, (req, res) => {
  const db = loadDB();
  const before = db.keys.length;
  db.keys = db.keys.filter(k => k.key !== req.params.key);
  saveDB(db);
  res.json({ success: true, deleted: before - db.keys.length });
});

app.get("/api/keys", auth, (req, res) => {
  const db = loadDB();
  res.json({ keys: db.keys });
});

app.post("/api/check-key", (req, res) => {
  const { key, uid } = req.body;
  if (!uid) return res.json({ valid: false, reason: "Thieu UID" });

  const db = loadDB();
  const item = db.keys.find(k => k.key === key);
  if (!item) return res.json({ valid: false, reason: "Key khong ton tai" });

  if (item.expiresAt && Date.now() > item.expiresAt)
    return res.json({ valid: false, reason: "Key het han" });

  if (!Array.isArray(item.usedBy)) item.usedBy = [];

  if (item.usedBy.includes(uid)) {
    return res.json({ valid: true, msg: "Da kich hoat" });
  }

  if (item.maxUses === 1 && item.usedBy.length >= 1) {
    return res.json({ valid: false, reason: "Key dung cho may khac" });
  }

  if (item.maxUses > 1 && item.usedBy.length >= item.maxUses) {
    return res.json({ valid: false, reason: "Key het slot" });
  }

  item.usedBy.push(uid);
  saveDB(db);
  res.json({ valid: true, msg: "Kich hoat thanh cong" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server chay port " + PORT));

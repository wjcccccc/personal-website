require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── uploads directory ────────────────────────────────────────────────────────
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

// ─── Security headers ─────────────────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],         // inline onclick needed
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'", 'https://fonts.googleapis.com', 'https://fonts.gstatic.com'],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],                       // clickjacking protection
        upgradeInsecureRequests: null,                    // disable on localhost (HTTP)
        scriptSrcAttr: ["'unsafe-inline'"],               // allow onclick attributes
      },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: false,
    hsts: false,
  })
);

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// ─── Session ──────────────────────────────────────────────────────────────────
app.use(
  session({
    store: new SQLiteStore({ db: 'sessions.sqlite', dir: '.' }),
    secret: process.env.SESSION_SECRET || 'ntu-network-security-2026-CHANGE-THIS',
    resave: false,
    saveUninitialized: false,
    name: 'sid',                // don't reveal express-session
    cookie: {
      httpOnly: true,           // JS cannot read the cookie
      sameSite: 'strict',       // CSRF mitigation
      maxAge: 7 * 24 * 60 * 60 * 1000,
      // secure: true            // enable when served over HTTPS
    },
  })
);

// ─── Static files (public only, NOT uploads) ──────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ─── Rate limiters ────────────────────────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 10,
  message: { error: '登入嘗試過多，請 15 分鐘後再試' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,  // 1 hour
  max: 5,
  message: { error: '註冊次數過多，請 1 小時後再試' },
  standardHeaders: true,
  legacyHeaders: false,
});

const uploadLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,  // 10 minutes
  max: 20,
  message: { error: '上傳過於頻繁，請稍後再試' },
});

// ─── CSRF middleware ──────────────────────────────────────────────────────────
// All state-changing API routes (except login/register) must include X-CSRF-Token header.
function ensureCsrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  return req.session.csrfToken;
}

function csrfProtect(req, res, next) {
  const token = req.headers['x-csrf-token'];
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  next();
}

app.get('/api/csrf-token', (req, res) => {
  res.json({ token: ensureCsrfToken(req) });
});

// ─── File upload (memory storage → magic byte check → disk) ──────────────────
const MAGIC = {
  jpg: [0xff, 0xd8, 0xff],
  png: [0x89, 0x50, 0x4e, 0x47],
};

function isValidImageBuffer(buf) {
  if (!buf || buf.length < 8) return false;
  const isJpeg = buf[0] === MAGIC.jpg[0] && buf[1] === MAGIC.jpg[1] && buf[2] === MAGIC.jpg[2];
  const isPng  = buf[0] === MAGIC.png[0] && buf[1] === MAGIC.png[1] &&
                 buf[2] === MAGIC.png[2] && buf[3] === MAGIC.png[3];
  return isJpeg || isPng;
}

function getImageExt(buf) {
  if (buf[0] === MAGIC.jpg[0] && buf[1] === MAGIC.jpg[1] && buf[2] === MAGIC.jpg[2]) return '.jpg';
  if (buf[0] === MAGIC.png[0]) return '.png';
  return null;
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (!allowed.includes(ext)) {
      return cb(new Error('Only jpg and png files are allowed'));
    }
    cb(null, true);
  },
});

// Write buffer to disk after magic byte validation
function saveUploadedImage(buf) {
  if (!isValidImageBuffer(buf)) {
    throw new Error('Only jpg and png files are allowed');
  }
  const ext = getImageExt(buf);
  const filename = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${ext}`;
  fs.writeFileSync(path.join(uploadsDir, filename), buf);
  return filename;
}

// ─── Serve uploaded images (explicit Content-Type, no execution risk) ─────────
const UPLOAD_CONTENT_TYPE = { '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png' };

app.get('/uploads/:filename', (req, res) => {
  // Only allow safe filenames: alphanumeric, dash, underscore, dot + extension
  const filename = req.params.filename;
  if (!/^[\w\-]+(\.jpg|\.jpeg|\.png)$/i.test(filename)) {
    return res.status(400).send('Invalid filename');
  }

  const filePath = path.join(uploadsDir, filename);
  if (!fs.existsSync(filePath)) return res.status(404).send('Not found');

  const ext = path.extname(filename).toLowerCase();
  const contentType = UPLOAD_CONTENT_TYPE[ext];
  if (!contentType) return res.status(400).send('Invalid file type');

  res.setHeader('Content-Type', contentType);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Disposition', 'inline');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.sendFile(filePath);
});

// ─── Auth helpers ─────────────────────────────────────────────────────────────
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  next();
}

// ─── Register ─────────────────────────────────────────────────────────────────
app.post('/api/register', registerLimiter, upload.single('avatar'), async (req, res) => {
  try {
    const username = (req.body.username || '').trim();
    const password = req.body.password || '';

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    if (username.length < 3 || username.length > 30) {
      return res.status(400).json({ error: 'Username must be 3–30 characters' });
    }
    // Only allow safe characters in username
    if (!/^[\w\-]+$/.test(username)) {
      return res.status(400).json({ error: 'Username may only contain letters, numbers, _ and -' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (existing) {
      return res.status(409).json({ error: 'Username already taken' });
    }

    let avatarPath = null;
    if (req.file) {
      try {
        const filename = saveUploadedImage(req.file.buffer);
        avatarPath = `/uploads/${filename}`;
      } catch {
        return res.status(400).json({ error: 'Only jpg and png files are allowed' });
      }
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const result = db
      .prepare('INSERT INTO users (username, password_hash, avatar_path) VALUES (?, ?, ?)')
      .run(username, passwordHash, avatarPath);

    // Regenerate session to prevent session fixation
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Session error' });
      req.session.userId = result.lastInsertRowid;
      req.session.username = username;
      ensureCsrfToken(req);
      res.json({ success: true, username, avatarPath });
    });
  } catch (err) {
    console.error('Register error:', err.message);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ─── Login ────────────────────────────────────────────────────────────────────
app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const username = (req.body.username || '').trim();
    const password = req.body.password || '';

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

    // Always run bcrypt to prevent timing attacks (even if user not found)
    const dummyHash = '$2b$12$invalidhashusedfortimingprotection000000000000000000000';
    const match = await bcrypt.compare(password, user ? user.password_hash : dummyHash);

    if (!user || !match) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Regenerate session to prevent session fixation
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Session error' });
      req.session.userId = user.id;
      req.session.username = user.username;
      ensureCsrfToken(req);
      res.json({ success: true, username: user.username, avatarPath: user.avatar_path });
    });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ─── Logout ───────────────────────────────────────────────────────────────────
app.post('/api/logout', requireLogin, csrfProtect, (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// ─── Current user ─────────────────────────────────────────────────────────────
app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });
  const user = db
    .prepare('SELECT id, username, avatar_path FROM users WHERE id = ?')
    .get(req.session.userId);
  if (!user) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, username: user.username, avatarPath: user.avatar_path });
});

// ─── Upload avatar ────────────────────────────────────────────────────────────
app.post('/api/upload-avatar', requireLogin, csrfProtect, uploadLimiter,
  upload.single('avatar'), (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

      let filename;
      try {
        filename = saveUploadedImage(req.file.buffer);
      } catch {
        return res.status(400).json({ error: 'Only jpg and png files are allowed' });
      }

      // Delete old avatar
      const user = db.prepare('SELECT avatar_path FROM users WHERE id = ?').get(req.session.userId);
      if (user && user.avatar_path) {
        const oldFilename = path.basename(user.avatar_path);
        const oldPath = path.join(uploadsDir, oldFilename);
        if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
      }

      const avatarPath = `/uploads/${filename}`;
      db.prepare('UPDATE users SET avatar_path = ? WHERE id = ?').run(avatarPath, req.session.userId);

      res.json({ success: true, avatarPath });
    } catch (err) {
      console.error('Upload error:', err.message);
      res.status(500).json({ error: 'Upload failed' });
    }
  }
);

// ─── Get messages ─────────────────────────────────────────────────────────────
app.get('/api/messages', (req, res) => {
  const messages = db
    .prepare(
      `SELECT m.id, m.content, m.created_at, u.username, u.avatar_path
       FROM messages m
       JOIN users u ON m.user_id = u.id
       ORDER BY m.created_at DESC`
    )
    .all();
  res.json(messages);
});

// ─── Post message ─────────────────────────────────────────────────────────────
app.post('/api/messages', requireLogin, csrfProtect, (req, res) => {
  try {
    const content = (req.body.content || '').trim();
    if (!content) return res.status(400).json({ error: 'Message cannot be empty' });
    if (content.length > 1000) return res.status(400).json({ error: 'Message too long (max 1000 chars)' });

    const result = db
      .prepare('INSERT INTO messages (user_id, content) VALUES (?, ?)')
      .run(req.session.userId, content);

    const message = db
      .prepare(
        `SELECT m.id, m.content, m.created_at, u.username, u.avatar_path
         FROM messages m
         JOIN users u ON m.user_id = u.id
         WHERE m.id = ?`
      )
      .get(result.lastInsertRowid);

    res.json(message);
  } catch (err) {
    console.error('Message error:', err.message);
    res.status(500).json({ error: 'Failed to post message' });
  }
});

// ─── Delete message ───────────────────────────────────────────────────────────
app.delete('/api/messages/:id', requireLogin, csrfProtect, (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid message id' });

    const message = db.prepare('SELECT user_id FROM messages WHERE id = ?').get(id);
    if (!message) return res.status(404).json({ error: 'Message not found' });
    if (message.user_id !== req.session.userId) {
      return res.status(403).json({ error: 'Cannot delete others\' messages' });
    }

    db.prepare('DELETE FROM messages WHERE id = ?').run(id);
    res.json({ success: true });
  } catch (err) {
    console.error('Delete error:', err.message);
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

// ─── Error handler ────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ error: 'File too large (max 5MB)' });
  }
  if (err.message === 'Only jpg and png files are allowed') {
    return res.status(400).json({ error: err.message });
  }
  // Don't leak internal error details
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

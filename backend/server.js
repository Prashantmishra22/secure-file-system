const express     = require('express');
const multer      = require('multer');
const bcrypt      = require('bcrypt');
const cors        = require('cors');
const crypto      = require('crypto');
const fs          = require('fs');
const path        = require('path');
const jwt         = require('jsonwebtoken');
const speakeasy   = require('speakeasy');
const QRCode      = require('qrcode');
const rateLimit   = require('express-rate-limit');
const helmet      = require('helmet');
const { detectMalware, detectBufferOverflow, logThreat, getThreats } = require('./security');

const app = express();

/* ───────── SECURITY HEADERS ───────── */
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(cors({ origin: '*', exposedHeaders: ['Authorization'] }));

/* ───────── SERVE FRONTEND ───────── */
app.use(express.static(path.join(__dirname, '..', 'frontend')));

/* ───────── JWT SECRET (persisted so sessions survive restarts) ───────── */
const JWT_SECRET_FILE = path.join(__dirname, 'jwt-secret.txt');
const JWT_SECRET = (() => {
  if (fs.existsSync(JWT_SECRET_FILE)) return fs.readFileSync(JWT_SECRET_FILE, 'utf8').trim();
  const secret = crypto.randomBytes(64).toString('hex');
  fs.writeFileSync(JWT_SECRET_FILE, secret);
  return secret;
})();

/* ───────── DIRS & FILES ───────── */
const UPLOADS_DIR  = path.join(__dirname, 'uploads');
const USERS_FILE   = path.join(__dirname, 'users.json');
const FILES_FILE   = path.join(__dirname, 'files.json');

if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);

/* ───────── PERSISTENCE HELPERS ───────── */
function loadJSON(file, fallback = []) {
  if (fs.existsSync(file)) {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
  }
  return fallback;
}
function saveJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

let users = loadJSON(USERS_FILE);
let files = loadJSON(FILES_FILE);

function saveUsers() { saveJSON(USERS_FILE, users); }
function saveFiles() { saveJSON(FILES_FILE, files); }

/* ───────── STARTUP MIGRATION — backfill missing user fields ───────── */
let migrated = false;
users.forEach(u => {
  if (u.role === undefined)             { u.role = 'user';  migrated = true; }
  if (u.twoFactorEnabled === undefined) { u.twoFactorEnabled = false; migrated = true; }
  if (u.twoFactorSecret === undefined)  { u.twoFactorSecret = null;  migrated = true; }
  if (u.createdAt === undefined)        { u.createdAt = new Date().toISOString(); migrated = true; }
});
if (migrated) { saveUsers(); console.log('⚙️  Migrated legacy user records'); }

/* ───────── MULTER — memory storage for magic byte checks ───────── */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }
});

/* ───────── RATE LIMITERS ───────── */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15 minutes
  max:      10,
  message:  'Too many attempts. Please try again in 15 minutes.',
  handler: (req, res, next, options) => {
    logThreat(req.body?.username || 'unknown', 'BRUTE_FORCE',
      `Rate limit hit on ${req.path}`, req.ip);
    res.status(429).json({ error: options.message });
  }
});

const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15 minutes
  max:      30,               // 30 uploads per window
  message:  'Too many uploads. Please try again later.',
  handler: (req, res, next, options) => {
    logThreat(req.user?.username || 'unknown', 'BRUTE_FORCE',
      'Upload rate limit hit', req.ip);
    res.status(429).json({ error: options.message });
  }
});

/* ───────── JWT MIDDLEWARE ───────── */
function requireAuth(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) {
    logThreat('unknown', 'UNAUTHORIZED', `No token on ${req.path}`, req.ip);
    return res.status(401).json({ error: 'Authorization required' });
  }
  try {
    const payload = jwt.verify(auth.slice(7), JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

/* ───────── SIGNUP ───────── */
app.post('/signup', authLimiter, async (req, res) => {
  // Buffer overflow check
  const bof = detectBufferOverflow(req);
  if (!bof.safe) {
    logThreat(req.body?.username || 'unknown', 'BUFFER_OVERFLOW', bof.reason, req.ip);
    return res.status(400).json({ error: bof.reason });
  }

  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Fill all fields' });

  if (username.length > 100)
    return res.status(400).json({ error: 'Username too long' });

  if (users.find(u => u.username === username))
    return res.status(400).json({ error: 'User already exists' });

  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const hash = await bcrypt.hash(password, 12);
  users.push({
    username,
    password: hash,
    twoFactorEnabled: false,
    twoFactorSecret: null,
    createdAt: new Date().toISOString(),
    role: 'user'
  });
  saveUsers();
  res.json({ message: 'Signup successful' });
});

/* ───────── LOGIN ───────── */
app.post('/login', authLimiter, async (req, res) => {
  const bof = detectBufferOverflow(req);
  if (!bof.safe) {
    logThreat(req.body?.username || 'unknown', 'BUFFER_OVERFLOW', bof.reason, req.ip);
    return res.status(400).json({ error: bof.reason });
  }

  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (!user) return res.status(400).json({ error: 'User not found' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    logThreat(username, 'BRUTE_FORCE', 'Failed login attempt', req.ip);
    return res.status(400).json({ error: 'Wrong password' });
  }

  // If 2FA is enabled, issue a partial token and require OTP
  if (user.twoFactorEnabled) {
    const partialToken = jwt.sign(
      { username, partial: true },
      JWT_SECRET,
      { expiresIn: '5m' }
    );
    return res.json({ requires2FA: true, partialToken });
  }

  // Full session token
  const token = jwt.sign({ username, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token, username });
});

/* ───────── 2FA SETUP (Generate QR) ───────── */
app.post('/2fa/setup', requireAuth, async (req, res) => {
  const user = users.find(u => u.username === req.user.username);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const secret = speakeasy.generateSecret({
    name: `SecureFS (${req.user.username})`,
    length: 20
  });

  user.twoFactorSecret = secret.base32;
  saveUsers();

  const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);
  res.json({ secret: secret.base32, qr: qrDataUrl });
});

/* ───────── 2FA ENABLE (Confirm OTP) ───────── */
app.post('/2fa/enable', requireAuth, (req, res) => {
  const { token } = req.body;
  const user = users.find(u => u.username === req.user.username);
  if (!user || !user.twoFactorSecret)
    return res.status(400).json({ error: '2FA not set up yet' });

  const valid = speakeasy.totp.verify({
    secret: user.twoFactorSecret,
    encoding: 'base32',
    token,
    window: 1
  });

  if (!valid) return res.status(400).json({ error: 'Invalid OTP code' });

  user.twoFactorEnabled = true;
  saveUsers();
  res.json({ message: '2FA enabled successfully' });
});

/* ───────── 2FA DISABLE ───────── */
app.post('/2fa/disable', requireAuth, async (req, res) => {
  const { password } = req.body;
  const user = users.find(u => u.username === req.user.username);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: 'Incorrect password' });

  user.twoFactorEnabled = false;
  user.twoFactorSecret  = null;
  saveUsers();
  res.json({ message: '2FA disabled' });
});

/* ───────── 2FA VERIFY (Complete Login) ───────── */
app.post('/2fa/verify', authLimiter, (req, res) => {
  const { token: otpCode, partialToken } = req.body;

  let payload;
  try {
    payload = jwt.verify(partialToken, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Session expired. Please log in again.' });
  }

  if (!payload.partial) return res.status(400).json({ error: 'Invalid token type' });

  const user = users.find(u => u.username === payload.username);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const valid = speakeasy.totp.verify({
    secret: user.twoFactorSecret,
    encoding: 'base32',
    token: otpCode,
    window: 1
  });

  if (!valid) {
    logThreat(user.username, 'BRUTE_FORCE', '2FA code verification failed', req.ip);
    return res.status(400).json({ error: 'Invalid 2FA code' });
  }

  const fullToken = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token: fullToken, username: user.username });
});

/* ───────── GET 2FA STATUS ───────── */
app.get('/2fa/status', requireAuth, (req, res) => {
  const user = users.find(u => u.username === req.user.username);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ enabled: user.twoFactorEnabled });
});

/* ───────── UPLOAD ───────── */
app.post('/upload', requireAuth, uploadLimiter, upload.single('file'), (req, res) => {
  try {
    const file     = req.file;
    const username = req.user.username;

    if (!file) return res.status(400).json({ error: 'No file provided' });

    // Buffer overflow check on filename
    const bof = detectBufferOverflow(req);
    if (!bof.safe) {
      logThreat(username, 'BUFFER_OVERFLOW', bof.reason, req.ip);
      return res.status(400).json({ error: bof.reason });
    }

    // Malware detection
    const scan = detectMalware(file);
    if (!scan.safe) {
      logThreat(username, 'MALWARE', `${scan.reason} — file: ${file.originalname}`, req.ip);
      return res.status(400).json({ error: `Security threat detected: ${scan.reason}` });
    }

    // Encrypt file buffer (AES-256-CBC)
    const key    = crypto.randomBytes(32);
    const iv     = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

    const encrypted = Buffer.concat([cipher.update(file.buffer), cipher.final()]);
    const encName   = crypto.randomBytes(16).toString('hex') + '.enc';
    const encPath   = path.join(UPLOADS_DIR, encName);
    fs.writeFileSync(encPath, encrypted);

    files.push({
      id:           crypto.randomBytes(8).toString('hex'),
      owner:        username,
      name:         file.originalname,
      encName,
      path:         encPath,
      key:          key.toString('hex'),
      iv:           iv.toString('hex'),
      size:         file.size,
      mimetype:     file.mimetype,
      uploadedAt:   new Date().toISOString(),
      sharedWith:   [],
      accessLog:    []
    });
    saveFiles();

    res.json({ message: 'File encrypted & uploaded successfully' });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

/* ───────── SIZE ERROR ───────── */
app.use((err, req, res, next) => {
  if (err.code === 'LIMIT_FILE_SIZE')
    return res.status(400).json({ error: 'File must be less than 5MB' });
  next(err);
});

/* ───────── LIST FILES (own + shared) ───────── */
app.get('/files', requireAuth, (req, res) => {
  const username = req.user.username;
  const ownFiles = files
    .filter(f => f.owner === username)
    .map(f => ({
      id: f.id, name: f.name, size: f.size, mimetype: f.mimetype,
      uploadedAt: f.uploadedAt, sharedWith: f.sharedWith, owned: true
    }));

  const sharedFiles = files
    .filter(f => f.sharedWith && f.sharedWith.includes(username))
    .map(f => ({
      id: f.id, name: f.name, size: f.size, mimetype: f.mimetype,
      uploadedAt: f.uploadedAt, owner: f.owner, owned: false
    }));

  res.json({ owned: ownFiles, shared: sharedFiles });
});

/* ───────── METADATA ───────── */
app.get('/metadata/:id', requireAuth, (req, res) => {
  const username = req.user.username;
  const file = files.find(f =>
    f.id === req.params.id &&
    (f.owner === username || (f.sharedWith && f.sharedWith.includes(username)))
  );
  if (!file) return res.status(404).json({ error: 'File not found' });

  res.json({
    id:          file.id,
    name:        file.name,
    size:        file.size,
    mimetype:    file.mimetype,
    uploadedAt:  file.uploadedAt,
    owner:       file.owner,
    sharedWith:  file.sharedWith,
    encryption:  'AES-256-CBC',
    accessLog:   file.accessLog || []
  });
});

/* ───────── DOWNLOAD ───────── */
app.get('/download/:id', requireAuth, (req, res) => {
  const username = req.user.username;
  const file = files.find(f =>
    f.id === req.params.id &&
    (f.owner === username || (f.sharedWith && f.sharedWith.includes(username)))
  );

  if (!file) return res.status(404).json({ error: 'File not found or access denied' });

  // Log access
  file.accessLog = file.accessLog || [];
  file.accessLog.push({ by: username, at: new Date().toISOString(), action: 'download' });
  saveFiles();

  const key     = Buffer.from(file.key, 'hex');
  const iv      = Buffer.from(file.iv, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

  const encData   = fs.readFileSync(file.path);
  const decrypted = Buffer.concat([decipher.update(encData), decipher.final()]);

  res.setHeader('Content-Disposition', `attachment; filename="${file.name}"`);
  res.setHeader('Content-Type', file.mimetype || 'application/octet-stream');
  res.send(decrypted);
});

/* ───────── SHARE FILE ───────── */
app.post('/share/:id', requireAuth, (req, res) => {
  const username     = req.user.username;
  const { shareWith } = req.body;

  if (!shareWith) return res.status(400).json({ error: 'Provide a username to share with' });
  if (shareWith === username) return res.status(400).json({ error: 'Cannot share with yourself' });

  const file = files.find(f => f.id === req.params.id && f.owner === username);
  if (!file) return res.status(404).json({ error: 'File not found or not owned by you' });

  const targetUser = users.find(u => u.username === shareWith);
  if (!targetUser) return res.status(404).json({ error: 'Target user not found' });

  if (!file.sharedWith.includes(shareWith)) {
    file.sharedWith.push(shareWith);
    file.accessLog = file.accessLog || [];
    file.accessLog.push({ by: username, at: new Date().toISOString(), action: `shared with ${shareWith}` });
    saveFiles();
  }

  res.json({ message: `File shared with ${shareWith}` });
});

/* ───────── UNSHARE FILE ───────── */
app.post('/unshare/:id', requireAuth, (req, res) => {
  const username     = req.user.username;
  const { unshareWith } = req.body;

  const file = files.find(f => f.id === req.params.id && f.owner === username);
  if (!file) return res.status(404).json({ error: 'File not found or not owned by you' });

  file.sharedWith = file.sharedWith.filter(u => u !== unshareWith);
  saveFiles();
  res.json({ message: `File access revoked for ${unshareWith}` });
});

/* ───────── DELETE ───────── */
app.delete('/delete/:id', requireAuth, (req, res) => {
  const username = req.user.username;
  const index    = files.findIndex(f => f.id === req.params.id && f.owner === username);

  if (index === -1) return res.status(404).json({ error: 'File not found or not owned by you' });

  const file = files[index];
  if (fs.existsSync(file.path)) fs.unlinkSync(file.path);

  files.splice(index, 1);
  saveFiles();
  res.json({ message: 'File deleted' });
});

/* ───────── SECURITY LOG ───────── */
app.get('/security-log', requireAuth, (req, res) => {
  res.json(getThreats(req.user.username));
});

/* ───────── USER SEARCH (for sharing) ───────── */
app.get('/users/search', requireAuth, (req, res) => {
  const q = (req.query.q || '').toLowerCase();
  if (q.length < 2) return res.json([]);
  const me = req.user.username;
  const results = users
    .filter(u => u.username !== me && u.username.toLowerCase().includes(q))
    .map(u => ({ username: u.username }))
    .slice(0, 10);
  res.json(results);
});

/* ───────── START ───────── */
app.listen(3000, () => {
  console.log('🔐 Secure File System running → http://localhost:3000');
  console.log('🛡️  Security modules: JWT auth, 2FA, malware scan, overflow detection');
});
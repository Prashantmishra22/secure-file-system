const express     = require('express');
const multer      = require('multer');
const bcrypt      = require('bcrypt');
const cors        = require('cors');
const crypto      = require('crypto');
const path        = require('path');
const jwt         = require('jsonwebtoken');
const speakeasy   = require('speakeasy');
const QRCode      = require('qrcode');
const rateLimit   = require('express-rate-limit');
const helmet      = require('helmet');
const mongoose    = require('mongoose');

const { detectMalware, detectBufferOverflow, logThreat, getThreats } = require('./security');
const User   = require('./models/User');
const File   = require('./models/File');

const app = express();

/* ───────── ENVIRONMENT ───────── */
const PORT         = process.env.PORT || 3000;
const MONGODB_URI  = process.env.MONGODB_URI || 'mongodb://localhost:27017/secure-file-system';
const JWT_SECRET   = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

/* ───────── MONGODB CONNECTION ───────── */
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => {
    console.error('❌ MongoDB connection error:', err.message);
    console.error('   Make sure MONGODB_URI environment variable is set correctly.');
    process.exit(1);
  });

/* ───────── SECURITY HEADERS ───────── */
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(cors({ origin: '*', exposedHeaders: ['Authorization'] }));

// Trust proxy for correct IP detection behind Render/Railway
app.set('trust proxy', 1);

/* ───────── SERVE FRONTEND ───────── */
app.use(express.static(path.join(__dirname, '..', 'frontend')));

/* ───────── MULTER — memory storage for magic byte checks ───────── */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }
});

/* ───────── RATE LIMITERS ───────── */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15 minutes
  max:      20,
  message:  'Too many attempts. Please try again in 15 minutes.',
  handler: (req, res, next, options) => {
    logThreat(req.body?.username || 'unknown', 'BRUTE_FORCE',
      `Rate limit hit on ${req.path}`, req.ip);
    res.status(429).json({ error: options.message });
  }
});

const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      30,
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

/* ───────── HEALTH CHECK ───────── */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    timestamp: new Date().toISOString()
  });
});

/* ───────── SIGNUP ───────── */
app.post('/signup', authLimiter, async (req, res) => {
  try {
    const bof = detectBufferOverflow(req);
    if (!bof.safe) {
      await logThreat(req.body?.username || 'unknown', 'BUFFER_OVERFLOW', bof.reason, req.ip);
      return res.status(400).json({ error: bof.reason });
    }

    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Fill all fields' });

    if (username.length > 100)
      return res.status(400).json({ error: 'Username too long' });

    const existing = await User.findOne({ username });
    if (existing)
      return res.status(400).json({ error: 'User already exists' });

    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const hash = await bcrypt.hash(password, 12);
    await User.create({ username, password: hash });

    res.json({ message: 'Signup successful' });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Server error during signup' });
  }
});

/* ───────── LOGIN ───────── */
app.post('/login', authLimiter, async (req, res) => {
  try {
    const bof = detectBufferOverflow(req);
    if (!bof.safe) {
      await logThreat(req.body?.username || 'unknown', 'BUFFER_OVERFLOW', bof.reason, req.ip);
      return res.status(400).json({ error: bof.reason });
    }

    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user) return res.status(400).json({ error: 'User not found' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      await logThreat(username, 'BRUTE_FORCE', 'Failed login attempt', req.ip);
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
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

/* ───────── 2FA SETUP (Generate QR) ───────── */
app.post('/2fa/setup', requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const secret = speakeasy.generateSecret({
      name: `SecureFS (${req.user.username})`,
      length: 20
    });

    user.twoFactorSecret = secret.base32;
    await user.save();

    const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);
    res.json({ secret: secret.base32, qr: qrDataUrl });
  } catch (err) {
    console.error('2FA setup error:', err);
    res.status(500).json({ error: 'Server error during 2FA setup' });
  }
});

/* ───────── 2FA ENABLE (Confirm OTP) ───────── */
app.post('/2fa/enable', requireAuth, async (req, res) => {
  try {
    const { token } = req.body;
    const user = await User.findOne({ username: req.user.username });
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
    await user.save();
    res.json({ message: '2FA enabled successfully' });
  } catch (err) {
    console.error('2FA enable error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ───────── 2FA DISABLE ───────── */
app.post('/2fa/disable', requireAuth, async (req, res) => {
  try {
    const { password } = req.body;
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Incorrect password' });

    user.twoFactorEnabled = false;
    user.twoFactorSecret  = null;
    await user.save();
    res.json({ message: '2FA disabled' });
  } catch (err) {
    console.error('2FA disable error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ───────── 2FA VERIFY (Complete Login) ───────── */
app.post('/2fa/verify', authLimiter, async (req, res) => {
  try {
    const { token: otpCode, partialToken } = req.body;

    let payload;
    try {
      payload = jwt.verify(partialToken, JWT_SECRET);
    } catch {
      return res.status(401).json({ error: 'Session expired. Please log in again.' });
    }

    if (!payload.partial) return res.status(400).json({ error: 'Invalid token type' });

    const user = await User.findOne({ username: payload.username });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const valid = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: otpCode,
      window: 1
    });

    if (!valid) {
      await logThreat(user.username, 'BRUTE_FORCE', '2FA code verification failed', req.ip);
      return res.status(400).json({ error: 'Invalid 2FA code' });
    }

    const fullToken = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token: fullToken, username: user.username });
  } catch (err) {
    console.error('2FA verify error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ───────── GET 2FA STATUS ───────── */
app.get('/2fa/status', requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ enabled: user.twoFactorEnabled });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

/* ───────── UPLOAD ───────── */
app.post('/upload', requireAuth, uploadLimiter, upload.single('file'), async (req, res) => {
  try {
    const file     = req.file;
    const username = req.user.username;

    if (!file) return res.status(400).json({ error: 'No file provided' });

    // Buffer overflow check on filename
    const bof = detectBufferOverflow(req);
    if (!bof.safe) {
      await logThreat(username, 'BUFFER_OVERFLOW', bof.reason, req.ip);
      return res.status(400).json({ error: bof.reason });
    }

    // Malware detection
    const scan = detectMalware(file);
    if (!scan.safe) {
      await logThreat(username, 'MALWARE', `${scan.reason} — file: ${file.originalname}`, req.ip);
      return res.status(400).json({ error: `Security threat detected: ${scan.reason}` });
    }

    // Encrypt file buffer (AES-256-CBC)
    const key    = crypto.randomBytes(32);
    const iv     = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

    const encrypted = Buffer.concat([cipher.update(file.buffer), cipher.final()]);

    // Store encrypted data in MongoDB (not on disk)
    await File.create({
      fileId:        crypto.randomBytes(8).toString('hex'),
      owner:         username,
      name:          file.originalname,
      encryptedData: encrypted,
      key:           key.toString('hex'),
      iv:            iv.toString('hex'),
      size:          file.size,
      mimetype:      file.mimetype,
      sharedWith:    [],
      accessLog:     []
    });

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
app.get('/files', requireAuth, async (req, res) => {
  try {
    const username = req.user.username;

    const ownFiles = await File.find({ owner: username })
      .select('fileId name size mimetype uploadedAt sharedWith')
      .lean();

    const sharedFiles = await File.find({ sharedWith: username })
      .select('fileId name size mimetype uploadedAt owner')
      .lean();

    const owned = ownFiles.map(f => ({
      id: f.fileId, name: f.name, size: f.size, mimetype: f.mimetype,
      uploadedAt: f.uploadedAt, sharedWith: f.sharedWith, owned: true
    }));

    const shared = sharedFiles.map(f => ({
      id: f.fileId, name: f.name, size: f.size, mimetype: f.mimetype,
      uploadedAt: f.uploadedAt, owner: f.owner, owned: false
    }));

    res.json({ owned, shared });
  } catch (err) {
    console.error('List files error:', err);
    res.status(500).json({ error: 'Failed to load files' });
  }
});

/* ───────── METADATA ───────── */
app.get('/metadata/:id', requireAuth, async (req, res) => {
  try {
    const username = req.user.username;
    const file = await File.findOne({
      fileId: req.params.id,
      $or: [{ owner: username }, { sharedWith: username }]
    }).select('-encryptedData -key -iv').lean();

    if (!file) return res.status(404).json({ error: 'File not found' });

    res.json({
      id:          file.fileId,
      name:        file.name,
      size:        file.size,
      mimetype:    file.mimetype,
      uploadedAt:  file.uploadedAt,
      owner:       file.owner,
      sharedWith:  file.sharedWith,
      encryption:  'AES-256-CBC',
      accessLog:   file.accessLog || []
    });
  } catch (err) {
    console.error('Metadata error:', err);
    res.status(500).json({ error: 'Failed to load metadata' });
  }
});

/* ───────── DOWNLOAD ───────── */
app.get('/download/:id', requireAuth, async (req, res) => {
  try {
    const username = req.user.username;
    const file = await File.findOne({
      fileId: req.params.id,
      $or: [{ owner: username }, { sharedWith: username }]
    });

    if (!file) return res.status(404).json({ error: 'File not found or access denied' });

    // Log access
    file.accessLog.push({ by: username, at: new Date().toISOString(), action: 'download' });
    await file.save();

    const key      = Buffer.from(file.key, 'hex');
    const iv       = Buffer.from(file.iv, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

    const decrypted = Buffer.concat([decipher.update(file.encryptedData), decipher.final()]);

    res.setHeader('Content-Disposition', `attachment; filename="${file.name}"`);
    res.setHeader('Content-Type', file.mimetype || 'application/octet-stream');
    res.send(decrypted);
  } catch (err) {
    console.error('Download error:', err);
    res.status(500).json({ error: 'Download failed' });
  }
});

/* ───────── SHARE FILE ───────── */
app.post('/share/:id', requireAuth, async (req, res) => {
  try {
    const username      = req.user.username;
    const { shareWith } = req.body;

    if (!shareWith) return res.status(400).json({ error: 'Provide a username to share with' });
    if (shareWith === username) return res.status(400).json({ error: 'Cannot share with yourself' });

    const file = await File.findOne({ fileId: req.params.id, owner: username });
    if (!file) return res.status(404).json({ error: 'File not found or not owned by you' });

    const targetUser = await User.findOne({ username: shareWith });
    if (!targetUser) return res.status(404).json({ error: 'Target user not found' });

    if (!file.sharedWith.includes(shareWith)) {
      file.sharedWith.push(shareWith);
      file.accessLog.push({ by: username, at: new Date().toISOString(), action: `shared with ${shareWith}` });
      await file.save();
    }

    res.json({ message: `File shared with ${shareWith}` });
  } catch (err) {
    console.error('Share error:', err);
    res.status(500).json({ error: 'Share failed' });
  }
});

/* ───────── UNSHARE FILE ───────── */
app.post('/unshare/:id', requireAuth, async (req, res) => {
  try {
    const username        = req.user.username;
    const { unshareWith } = req.body;

    const file = await File.findOne({ fileId: req.params.id, owner: username });
    if (!file) return res.status(404).json({ error: 'File not found or not owned by you' });

    file.sharedWith = file.sharedWith.filter(u => u !== unshareWith);
    await file.save();
    res.json({ message: `File access revoked for ${unshareWith}` });
  } catch (err) {
    console.error('Unshare error:', err);
    res.status(500).json({ error: 'Unshare failed' });
  }
});

/* ───────── DELETE ───────── */
app.delete('/delete/:id', requireAuth, async (req, res) => {
  try {
    const username = req.user.username;
    const result = await File.findOneAndDelete({ fileId: req.params.id, owner: username });

    if (!result) return res.status(404).json({ error: 'File not found or not owned by you' });

    res.json({ message: 'File deleted' });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Delete failed' });
  }
});

/* ───────── SECURITY LOG ───────── */
app.get('/security-log', requireAuth, async (req, res) => {
  try {
    const threats = await getThreats(req.user.username);
    res.json(threats);
  } catch (err) {
    console.error('Security log error:', err);
    res.status(500).json({ error: 'Failed to load security log' });
  }
});

/* ───────── USER SEARCH (for sharing) ───────── */
app.get('/users/search', requireAuth, async (req, res) => {
  try {
    const q = (req.query.q || '').toLowerCase();
    if (q.length < 2) return res.json([]);
    const me = req.user.username;
    const results = await User.find({
      username: { $regex: q, $options: 'i', $ne: me }
    })
      .select('username')
      .limit(10)
      .lean();

    res.json(results.filter(u => u.username !== me).map(u => ({ username: u.username })));
  } catch (err) {
    console.error('User search error:', err);
    res.status(500).json({ error: 'Search failed' });
  }
});

/* ───────── CATCH-ALL: serve index.html for SPA routes ───────── */
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});

/* ───────── START ───────── */
app.listen(PORT, () => {
  console.log(`🔐 Secure File System running → port ${PORT}`);
  console.log('🛡️  Security modules: JWT auth, 2FA, malware scan, overflow detection');
  console.log('🌍 Database: MongoDB Atlas');
});
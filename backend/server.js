require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
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
const nodemailer  = require('nodemailer');
const fs          = require('fs');

const { detectMalware, detectBufferOverflow, logThreat, getThreats } = require('./security');
const User     = require('./models/User');
const File     = require('./models/File');
const Activity = require('./models/Activity');
const Note     = require('./models/Note');
const Session  = require('./models/Session');

const ReportSchema = new mongoose.Schema({
  message: String,
  email: String,
  timestamp: Date
});
const Report = mongoose.model("Report", ReportSchema);

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Verify Nodemailer initially
if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
  transporter.verify((error, success) => {
    if (error) {
      console.error('❌ Nodemailer configuration error:', error);
    } else {
      console.log('✅ Nodemailer SMTP is ready to send emails');
    }
  });
} else {
  console.warn('⚠️ EMAIL_USER or EMAIL_PASS is missing in environment variables. Email functionality will be disabled.');
}

const app = express();

/* ───────── ENVIRONMENT ───────── */
const PORT         = process.env.PORT || 3000;
const JWT_SECRET   = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

/* ───────── MONGODB CONNECTION ───────── */
async function connectDB() {
  let uri = process.env.MONGODB_URI;

  if (!uri) {
    // No MONGODB_URI set → use in-memory MongoDB for local development
    const { MongoMemoryServer } = require('mongodb-memory-server');
    const mongod = await MongoMemoryServer.create();
    uri = mongod.getUri();
    console.log('🧪 Using in-memory MongoDB (local dev mode)');
    console.log('   Set MONGODB_URI env var for production/Atlas.');
  }

  await mongoose.connect(uri);
  console.log('✅ Connected to MongoDB');
}

connectDB().catch(err => {
  console.error('⚠️  MongoDB unavailable:', err.message);
  console.warn('⚠️  Running WITHOUT database — file/auth features disabled, email still works.');
});

/* ───────── SECURITY HEADERS ───────── */
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(cors({ 
  origin: '*', 
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Authorization'] 
}));

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
  windowMs: 15 * 60 * 1000,
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

/* ───────── ADMIN MIDDLEWARE ───────── */
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

/* ───────── ACTIVITY LOGGER ───────── */
async function logActivity(username, event, detail = '', ip = 'unknown') {
  try {
    await Activity.create({ username, event, detail, ip });
  } catch (err) {
    console.error('Activity log error:', err.message);
  }
}

app.post("/report", async (req, res) => {
  try {
    const { message, email } = req.body;
    if (!message) {
      return res.status(400).json({ success: false, error: 'Message is required' });
    }

    // Try to save to MongoDB — skip silently if DB is not connected
    if (mongoose.connection.readyState === 1) {
      try {
        await Report.create({ message, email, timestamp: new Date() });
      } catch (dbErr) {
        console.warn('⚠️  DB save skipped:', dbErr.message);
      }
    } else {
      console.warn('⚠️  DB not connected — skipping report save, sending email only.');
    }

    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      console.error('❌ Missing EMAIL_USER or EMAIL_PASS environment variables!');
      return res.status(500).json({ success: false, error: 'Email configuration missing (EMAIL_USER/EMAIL_PASS not set)' });
    }

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER,
      replyTo: email || process.env.EMAIL_USER,
      subject: 'New Complaint from Website',
      text: `User Email: ${email || 'Anonymous'}\nMessage: ${message}`,
      html: `
        <h2>New Complaint from Website</h2>
        <p><strong>User Email:</strong> ${email || 'Not provided'}</p>
        <hr>
        <p><strong>Message:</strong></p>
        <p style="white-space: pre-wrap;">${message}</p>
      `
    };

    try {
      const info = await transporter.sendMail(mailOptions);
      console.log(`✅ Support email sent from ${email}. Message ID: ${info.messageId}`);
      res.json({ success: true });
    } catch (mailErr) {
      console.error('❌ Failed to send support email:', mailErr);
      res.status(500).json({ success: false, error: 'Failed to send email. Ensure Gmail App Password is correct.' });
    }

  } catch (err) {
    console.error('Report error:', err);
    res.status(500).json({ success: false, error: 'Server error processing report' });
  }
});

/* ───────── HEALTH CHECK ───────── */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    timestamp: new Date().toISOString()
  });
});

/* ═══════════════════════════════════════════════
   AUTH ENDPOINTS
   ═══════════════════════════════════════════════ */

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

    // First user automatically becomes admin
    const userCount = await User.countDocuments();
    const role = userCount === 0 ? 'admin' : 'user';

    await User.create({ username, password: hash, role });

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

    // Track session
    await Session.create({
      sessionId: crypto.randomBytes(16).toString('hex'),
      username,
      tokenHash: crypto.createHash('sha256').update(token).digest('hex'),
      userAgent: req.headers['user-agent'] || 'Unknown',
      ip: req.ip,
      expiresAt: new Date(Date.now() + 8 * 60 * 60 * 1000)
    });

    await logActivity(username, 'LOGIN', 'Logged in', req.ip);
    res.json({ token, username, role: user.role });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

/* ═══════════════════════════════════════════════
   2FA ENDPOINTS
   ═══════════════════════════════════════════════ */

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
    await logActivity(req.user.username, '2FA_ENABLED', '2FA enabled via TOTP', req.ip);
    res.json({ message: '2FA enabled successfully' });
  } catch (err) {
    console.error('2FA enable error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

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
    await logActivity(req.user.username, '2FA_DISABLED', '2FA disabled', req.ip);
    res.json({ message: '2FA disabled' });
  } catch (err) {
    console.error('2FA disable error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

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

    // Track session
    await Session.create({
      sessionId: crypto.randomBytes(16).toString('hex'),
      username: user.username,
      tokenHash: crypto.createHash('sha256').update(fullToken).digest('hex'),
      userAgent: req.headers['user-agent'] || 'Unknown',
      ip: req.ip,
      expiresAt: new Date(Date.now() + 8 * 60 * 60 * 1000)
    });

    await logActivity(user.username, 'LOGIN', 'Logged in with 2FA', req.ip);
    res.json({ token: fullToken, username: user.username, role: user.role });
  } catch (err) {
    console.error('2FA verify error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/2fa/status', requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ enabled: user.twoFactorEnabled });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

/* ═══════════════════════════════════════════════
   FILE ENDPOINTS (with versioning)
   ═══════════════════════════════════════════════ */

/* ───────── UPLOAD (with version support) ───────── */
app.post('/upload', requireAuth, uploadLimiter, upload.single('file'), async (req, res) => {
  try {
    const file     = req.file;
    const username = req.user.username;

    if (!file) return res.status(400).json({ error: 'No file provided' });

    const bof = detectBufferOverflow(req);
    if (!bof.safe) {
      await logThreat(username, 'BUFFER_OVERFLOW', bof.reason, req.ip);
      return res.status(400).json({ error: bof.reason });
    }

    const scan = detectMalware(file);
    if (!scan.safe) {
      await logThreat(username, 'MALWARE', `${scan.reason} — file: ${file.originalname}`, req.ip);
      return res.status(400).json({ error: `Security threat detected: ${scan.reason}` });
    }

    // Save file inside /backend/uploads
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    fs.writeFileSync(path.join(uploadDir, file.originalname), file.buffer);

    // Encrypt file buffer (AES-256-CBC)
    const key    = crypto.randomBytes(32);
    const iv     = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = Buffer.concat([cipher.update(file.buffer), cipher.final()]);

    // Check for existing file with same name (versioning)
    const existing = await File.findOne({ owner: username, name: file.originalname, isLatest: true });

    if (existing) {
      // Demote old version
      existing.isLatest = false;
      await existing.save();

      await File.create({
        fileId:        crypto.randomBytes(8).toString('hex'),
        owner:         username,
        name:          file.originalname,
        encryptedData: encrypted,
        key:           key.toString('hex'),
        iv:            iv.toString('hex'),
        size:          file.size,
        mimetype:      file.mimetype,
        sharedWith:    existing.sharedWith || [],
        accessLog:     [],
        version:       (existing.version || 1) + 1,
        isLatest:      true
      });
    } else {
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
        accessLog:     [],
        version:       1,
        isLatest:      true
      });
    }

    await logActivity(username, 'UPLOAD', `Uploaded ${file.originalname}`, req.ip);
    res.json({ success: true, message: 'File encrypted & uploaded successfully' });
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

    const ownFiles = await File.find({ owner: username, isLatest: { $ne: false } })
      .select('fileId name size mimetype uploadedAt sharedWith version')
      .lean();

    const sharedFiles = await File.find({ sharedWith: username, isLatest: { $ne: false } })
      .select('fileId name size mimetype uploadedAt owner version')
      .lean();

    const owned = ownFiles.map(f => ({
      id: f.fileId, name: f.name, size: f.size, mimetype: f.mimetype,
      uploadedAt: f.uploadedAt, sharedWith: f.sharedWith, owned: true,
      version: f.version || 1
    }));

    const shared = sharedFiles.map(f => ({
      id: f.fileId, name: f.name, size: f.size, mimetype: f.mimetype,
      uploadedAt: f.uploadedAt, owner: f.owner, owned: false,
      version: f.version || 1
    }));

    res.json({ owned, shared });
  } catch (err) {
    console.error('List files error:', err);
    res.status(500).json({ error: 'Failed to load files' });
  }
});

/* ───────── FILE VERSION HISTORY ───────── */
app.get('/versions/:name', requireAuth, async (req, res) => {
  try {
    const username = req.user.username;
    const fileName = decodeURIComponent(req.params.name);

    const versions = await File.find({ owner: username, name: fileName })
      .select('fileId name version size uploadedAt isLatest')
      .sort({ version: -1 })
      .lean();

    res.json(versions.map(v => ({
      id: v.fileId,
      version: v.version || 1,
      size: v.size,
      uploadedAt: v.uploadedAt,
      isLatest: v.isLatest !== false
    })));
  } catch (err) {
    console.error('Versions error:', err);
    res.status(500).json({ error: 'Failed to load versions' });
  }
});

/* ───────── RESTORE VERSION ───────── */
app.post('/restore/:id', requireAuth, async (req, res) => {
  try {
    const username = req.user.username;
    const file = await File.findOne({ fileId: req.params.id, owner: username });
    if (!file) return res.status(404).json({ error: 'File not found' });

    // Demote current latest
    await File.updateMany(
      { owner: username, name: file.name, isLatest: true },
      { isLatest: false }
    );

    // Promote this version
    file.isLatest = true;
    await file.save();

    await logActivity(username, 'FILE_RESTORED', `Restored v${file.version} of ${file.name}`, req.ip);
    res.json({ message: `Restored version ${file.version}` });
  } catch (err) {
    console.error('Restore error:', err);
    res.status(500).json({ error: 'Restore failed' });
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
      accessLog:   file.accessLog || [],
      version:     file.version || 1
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

    file.accessLog.push({ by: username, at: new Date().toISOString(), action: 'download' });
    await file.save();

    const key      = Buffer.from(file.key, 'hex');
    const iv       = Buffer.from(file.iv, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    const decrypted = Buffer.concat([decipher.update(file.encryptedData), decipher.final()]);

    await logActivity(username, 'DOWNLOAD', `Downloaded ${file.name}`, req.ip);

    res.setHeader('Content-Disposition', `attachment; filename="${file.name}"`);
    res.setHeader('Content-Type', file.mimetype || 'application/octet-stream');
    res.send(decrypted);
  } catch (err) {
    console.error('Download error:', err);
    res.status(500).json({ error: 'Download failed' });
  }
});

/* ───────── FILE PREVIEW ───────── */
app.get('/preview/:id', requireAuth, async (req, res) => {
  try {
    const username = req.user.username;
    const file = await File.findOne({
      fileId: req.params.id,
      $or: [{ owner: username }, { sharedWith: username }]
    });

    if (!file) return res.status(404).json({ error: 'File not found or access denied' });

    const key      = Buffer.from(file.key, 'hex');
    const iv       = Buffer.from(file.iv, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    const decrypted = Buffer.concat([decipher.update(file.encryptedData), decipher.final()]);

    // For text files, return as text
    const mime = (file.mimetype || '').toLowerCase();
    const ext = (file.name || '').split('.').pop().toLowerCase();
    const isText = ['txt', 'md', 'csv', 'json', 'xml', 'html', 'css', 'js', 'py', 'java', 'c', 'cpp', 'h', 'log', 'yml', 'yaml', 'ini', 'cfg', 'conf', 'sh', 'bat'].includes(ext);

    if (isText) {
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    } else {
      res.setHeader('Content-Type', mime || 'application/octet-stream');
    }
    res.setHeader('Content-Disposition', 'inline');
    res.send(decrypted);
  } catch (err) {
    console.error('Preview error:', err);
    res.status(500).json({ error: 'Preview failed' });
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

    await logActivity(username, 'SHARE', `Shared ${file.name} with ${shareWith}`, req.ip);
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
    await logActivity(username, 'UNSHARE', `Revoked ${unshareWith}'s access to ${file.name}`, req.ip);
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
    const file = await File.findOne({ fileId: req.params.id, owner: username });
    if (!file) return res.status(404).json({ error: 'File not found or not owned by you' });

    // Delete all versions of this file
    await File.deleteMany({ owner: username, name: file.name });
    await logActivity(username, 'DELETE', `Deleted ${file.name} (all versions)`, req.ip);
    res.json({ message: 'File deleted' });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Delete failed' });
  }
});

/* ═══════════════════════════════════════════════
   SECURITY LOG
   ═══════════════════════════════════════════════ */

app.get('/security-log', requireAuth, async (req, res) => {
  try {
    const threats = await getThreats(req.user.username);
    res.json(threats);
  } catch (err) {
    console.error('Security log error:', err);
    res.status(500).json({ error: 'Failed to load security log' });
  }
});

/* ═══════════════════════════════════════════════
   ACTIVITY TIMELINE
   ═══════════════════════════════════════════════ */

app.get('/activity', requireAuth, async (req, res) => {
  try {
    const activities = await Activity.find({ username: req.user.username })
      .sort({ timestamp: -1 })
      .limit(100)
      .lean();
    res.json(activities);
  } catch (err) {
    console.error('Activity error:', err);
    res.status(500).json({ error: 'Failed to load activity' });
  }
});

/* ═══════════════════════════════════════════════
   SESSION MANAGEMENT
   ═══════════════════════════════════════════════ */

app.get('/sessions', requireAuth, async (req, res) => {
  try {
    const sessions = await Session.find({ username: req.user.username })
      .sort({ loginAt: -1 })
      .lean();

    // Identify current session
    const currentTokenHash = crypto.createHash('sha256')
      .update(req.headers['authorization'].slice(7))
      .digest('hex');

    res.json(sessions.map(s => ({
      id: s.sessionId,
      userAgent: s.userAgent,
      ip: s.ip,
      loginAt: s.loginAt,
      isCurrent: s.tokenHash === currentTokenHash
    })));
  } catch (err) {
    console.error('Sessions error:', err);
    res.status(500).json({ error: 'Failed to load sessions' });
  }
});

app.delete('/sessions/:id', requireAuth, async (req, res) => {
  try {
    const result = await Session.findOneAndDelete({
      sessionId: req.params.id,
      username: req.user.username
    });
    if (!result) return res.status(404).json({ error: 'Session not found' });
    await logActivity(req.user.username, 'SESSION_REVOKED', 'Revoked a session', req.ip);
    res.json({ message: 'Session revoked' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to revoke session' });
  }
});

app.post('/sessions/revoke-all', requireAuth, async (req, res) => {
  try {
    const currentTokenHash = crypto.createHash('sha256')
      .update(req.headers['authorization'].slice(7))
      .digest('hex');

    await Session.deleteMany({
      username: req.user.username,
      tokenHash: { $ne: currentTokenHash }
    });
    await logActivity(req.user.username, 'SESSION_REVOKED', 'Revoked all other sessions', req.ip);
    res.json({ message: 'All other sessions revoked' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to revoke sessions' });
  }
});

/* ═══════════════════════════════════════════════
   PASSWORD CHANGE
   ═══════════════════════════════════════════════ */

app.post('/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword)
      return res.status(400).json({ error: 'Both current and new password are required' });

    if (newPassword.length < 8)
      return res.status(400).json({ error: 'New password must be at least 8 characters' });

    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const match = await bcrypt.compare(currentPassword, user.password);
    if (!match) return res.status(400).json({ error: 'Current password is incorrect' });

    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();

    await logActivity(req.user.username, 'PASSWORD_CHANGED', 'Password updated', req.ip);
    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    console.error('Password change error:', err);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

/* ═══════════════════════════════════════════════
   ENCRYPTED NOTES
   ═══════════════════════════════════════════════ */

app.get('/notes', requireAuth, async (req, res) => {
  try {
    const notes = await Note.find({ owner: req.user.username })
      .select('-encryptedData -key -iv')
      .sort({ updatedAt: -1 })
      .lean();

    res.json(notes.map(n => ({
      id:        n.noteId,
      title:     n.title,
      createdAt: n.createdAt,
      updatedAt: n.updatedAt
    })));
  } catch (err) {
    res.status(500).json({ error: 'Failed to load notes' });
  }
});

app.get('/notes/:id', requireAuth, async (req, res) => {
  try {
    const note = await Note.findOne({ noteId: req.params.id, owner: req.user.username });
    if (!note) return res.status(404).json({ error: 'Note not found' });

    // Decrypt
    const key      = Buffer.from(note.key, 'hex');
    const iv       = Buffer.from(note.iv, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    const decrypted = Buffer.concat([decipher.update(note.encryptedData), decipher.final()]);

    res.json({
      id:        note.noteId,
      title:     note.title,
      content:   decrypted.toString('utf8'),
      createdAt: note.createdAt,
      updatedAt: note.updatedAt
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to read note' });
  }
});

app.post('/notes', requireAuth, async (req, res) => {
  try {
    const { id, title, content } = req.body;
    if (!content && content !== '') return res.status(400).json({ error: 'Content is required' });

    const noteTitle = (title || 'Untitled Note').slice(0, 200);
    const plaintext = Buffer.from(content || '', 'utf8');

    const key    = crypto.randomBytes(32);
    const iv     = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);

    if (id) {
      // Update existing note
      const existing = await Note.findOne({ noteId: id, owner: req.user.username });
      if (!existing) return res.status(404).json({ error: 'Note not found' });

      existing.title = noteTitle;
      existing.encryptedData = encrypted;
      existing.key = key.toString('hex');
      existing.iv = iv.toString('hex');
      existing.updatedAt = new Date();
      await existing.save();

      res.json({ id: existing.noteId, message: 'Note updated' });
    } else {
      // Create new note
      const noteId = crypto.randomBytes(8).toString('hex');
      await Note.create({
        noteId,
        owner: req.user.username,
        title: noteTitle,
        encryptedData: encrypted,
        key: key.toString('hex'),
        iv: iv.toString('hex')
      });

      await logActivity(req.user.username, 'NOTE_CREATED', `Created note: ${noteTitle}`, req.ip);
      res.json({ id: noteId, message: 'Note created' });
    }
  } catch (err) {
    console.error('Note save error:', err);
    res.status(500).json({ error: 'Failed to save note' });
  }
});

app.delete('/notes/:id', requireAuth, async (req, res) => {
  try {
    const result = await Note.findOneAndDelete({ noteId: req.params.id, owner: req.user.username });
    if (!result) return res.status(404).json({ error: 'Note not found' });

    await logActivity(req.user.username, 'NOTE_DELETED', `Deleted note: ${result.title}`, req.ip);
    res.json({ message: 'Note deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete note' });
  }
});

/* ═══════════════════════════════════════════════
   ADMIN PANEL
   ═══════════════════════════════════════════════ */

app.get('/admin/stats', requireAuth, requireAdmin, async (req, res) => {
  try {
    const [totalUsers, totalFiles, totalThreats, totalNotes] = await Promise.all([
      User.countDocuments(),
      File.countDocuments({ isLatest: { $ne: false } }),
      require('./models/Threat').countDocuments(),
      Note.countDocuments()
    ]);

    // Estimate storage
    const files = await File.find().select('size').lean();
    const totalStorage = files.reduce((a, f) => a + (f.size || 0), 0);

    res.json({ totalUsers, totalFiles, totalThreats, totalNotes, totalStorage });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load stats' });
  }
});

app.get('/admin/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const users = await User.find()
      .select('username role twoFactorEnabled createdAt')
      .sort({ createdAt: -1 })
      .lean();
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load users' });
  }
});

app.delete('/admin/user/:username', requireAuth, requireAdmin, async (req, res) => {
  try {
    const target = req.params.username;
    if (target === req.user.username)
      return res.status(400).json({ error: 'Cannot delete yourself' });

    const user = await User.findOne({ username: target });
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Delete user's files, notes, sessions, activity
    await Promise.all([
      File.deleteMany({ owner: target }),
      Note.deleteMany({ owner: target }),
      Session.deleteMany({ username: target }),
      Activity.deleteMany({ username: target }),
      User.deleteOne({ username: target })
    ]);

    res.json({ message: `User ${target} and all their data deleted` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

app.get('/admin/threats', requireAuth, requireAdmin, async (req, res) => {
  try {
    const Threat = require('./models/Threat');
    const threats = await Threat.find()
      .sort({ timestamp: -1 })
      .limit(200)
      .lean();
    res.json(threats);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load threats' });
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

/* ═══════════════════════════════════════════════
   COMPLAINT EMAIL
   ═══════════════════════════════════════════════ */

// Removed duplicate nodemailer declaration
app.post('/api/complaint', async (req, res) => {
  try {
    const { message } = req.body;

    if (!message || !message.trim()) {
      return res.status(400).json({ success: false, error: 'Message is required' });
    }

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: 'pm9569mishraji@gmail.com',
      subject: 'New Complaint from Website',
      text: message.trim()
    });

    res.json({ success: true });
  } catch (err) {
    console.error('Complaint email error:', err.message);
    res.json({ success: false });
  }
});

/* ───────── CATCH-ALL: serve index.html for SPA routes ───────── */
app.get('/{*splat}', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});

/* ───────── START ───────── */
app.listen(PORT, () => {
  console.log(`🔐 Secure File System running → port ${PORT}`);
  console.log('🛡️  Security: JWT, 2FA, malware scan, overflow detection');
  console.log('📊 Features: Admin panel, activity log, versioning, sessions, notes, preview');
  console.log('🌍 Database: MongoDB Atlas');
});

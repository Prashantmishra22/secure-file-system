const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema({
  sessionId: { type: String, required: true, unique: true },
  username:  { type: String, required: true, index: true },
  tokenHash: { type: String, required: true },
  userAgent: { type: String, default: 'Unknown' },
  ip:        { type: String, default: 'unknown' },
  loginAt:   { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true }
});

// Auto-cleanup expired sessions
sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('Session', sessionSchema);

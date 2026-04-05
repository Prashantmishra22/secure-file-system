const mongoose = require('mongoose');

const threatSchema = new mongoose.Schema({
  username:  { type: String, required: true, index: true },
  type:      { type: String, required: true, enum: ['MALWARE', 'BUFFER_OVERFLOW', 'BRUTE_FORCE', 'UNAUTHORIZED'] },
  detail:    { type: String, required: true },
  ip:        { type: String, default: 'unknown' },
  timestamp: { type: String, default: () => new Date().toISOString() }
});

// Auto-expire old threats after 30 days
threatSchema.index({ timestamp: 1 }, { expireAfterSeconds: 30 * 24 * 60 * 60 });

module.exports = mongoose.model('Threat', threatSchema);

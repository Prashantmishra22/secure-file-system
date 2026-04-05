const mongoose = require('mongoose');

const activitySchema = new mongoose.Schema({
  username:  { type: String, required: true, index: true },
  event:     { type: String, required: true, enum: [
    'UPLOAD', 'DOWNLOAD', 'SHARE', 'UNSHARE', 'DELETE',
    'LOGIN', '2FA_ENABLED', '2FA_DISABLED', 'PASSWORD_CHANGED',
    'NOTE_CREATED', 'NOTE_DELETED', 'SESSION_REVOKED', 'FILE_RESTORED'
  ]},
  detail:    { type: String, default: '' },
  ip:        { type: String, default: 'unknown' },
  timestamp: { type: Date, default: Date.now }
});

activitySchema.index({ timestamp: -1 });

module.exports = mongoose.model('Activity', activitySchema);

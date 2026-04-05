const mongoose = require('mongoose');

const accessLogEntry = new mongoose.Schema({
  by:     { type: String, required: true },
  at:     { type: String, default: () => new Date().toISOString() },
  action: { type: String, required: true }
}, { _id: false });

const fileSchema = new mongoose.Schema({
  fileId:        { type: String, required: true, unique: true },
  owner:         { type: String, required: true, index: true },
  name:          { type: String, required: true },
  encryptedData: { type: Buffer, required: true },
  key:           { type: String, required: true },
  iv:            { type: String, required: true },
  size:          { type: Number, required: true },
  mimetype:      { type: String, default: 'application/octet-stream' },
  uploadedAt:    { type: String, default: () => new Date().toISOString() },
  sharedWith:    { type: [String], default: [] },
  accessLog:     { type: [accessLogEntry], default: [] }
});

// Index for querying shared files
fileSchema.index({ sharedWith: 1 });

module.exports = mongoose.model('File', fileSchema);

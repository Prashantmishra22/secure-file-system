const mongoose = require('mongoose');

const noteSchema = new mongoose.Schema({
  noteId:        { type: String, required: true, unique: true },
  owner:         { type: String, required: true, index: true },
  title:         { type: String, default: 'Untitled Note' },
  encryptedData: { type: Buffer, required: true },
  key:           { type: String, required: true },
  iv:            { type: String, required: true },
  createdAt:     { type: Date, default: Date.now },
  updatedAt:     { type: Date, default: Date.now }
});

module.exports = mongoose.model('Note', noteSchema);

const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username:         { type: String, required: true, unique: true, trim: true, maxlength: 100 },
  password:         { type: String, required: true },
  role:             { type: String, default: 'user', enum: ['user', 'admin'] },
  twoFactorEnabled: { type: Boolean, default: false },
  twoFactorSecret:  { type: String, default: null },
  createdAt:        { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);

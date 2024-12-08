const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Joi = require('joi');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  
 
  role: { type: String, enum: ['manager', 'user'], default: 'user' },
  status: { type: String, enum: ['active', 'suspended'], default: 'active' },
  refreshToken: String,
  created: { type: Date, default: Date.now },
}, {
  timestamps: true,
});



const User = mongoose.model('User', userSchema);
module.exports = User;
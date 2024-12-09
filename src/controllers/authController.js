const pool = require('../config/db'); // Import MySQL pool for DB connection
const jwtUtils = require('../utils/jwtUtils');
const passwordUtils = require('../utils/passwordUtils');
const joi = require('joi');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const schema = joi.object({
  email: joi.string().email().trim().required(),
  password: joi.string().min(6).required(),
  role: joi.string().required(),
});

const register = async (req, res) => {
  try {
    const { error } = schema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });

    const { email, password, role } = req.body;

    // Check if the user already exists
    const [existingUser] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (existingUser.length > 0) {
      return res.status(409).json({ error: 'Email already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log(hashedPassword);

    // Insert the new user into the database
    const [newUser] = await pool.execute(
      'INSERT INTO users (email, password, role) VALUES (?, ?, ?)',
      [email, hashedPassword, role]
    );
    console.log(newUser);

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

const login = async (req, res) => {
  const schema = joi.object({
    email: joi.string().email().trim().required(),
    password: joi.string().min(6).required(),
  });

  const { error } = schema.validate(req.body);
  if (error) return res.status(400).json({ error: error.details[0].message });

  const { email, password } = req.body;

  try {
    // Get user by email
    const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    const user = users[0];
    if (!user) return res.status(401).json({ error: 'User does not exist' });

    if (user.status !== 'active') return res.status(403).json({ error: 'User is suspended' });

    // Check if the password matches
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

    // Generate JWT tokens
    const accessToken = jwtUtils.generateAccessToken(user);
    const refreshToken = jwtUtils.generateRefreshToken(user);

    // Update refresh token in DB
    await pool.execute('UPDATE users SET refreshToken = ? WHERE id = ?', [refreshToken, user.id]);

    res.json({ accessToken, refreshToken });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

const refreshToken = async (req, res) => {
  const refreshToken = req.body.refreshToken;
  if (!refreshToken) return res.status(401).json({ error: 'Refresh token missing' });

  try {
    const decoded = jwt.verify(refreshToken, 'your_refresh_jwt_secret');
    const [users] = await pool.execute('SELECT * FROM users WHERE id = ? AND refreshToken = ?', [decoded.userId, refreshToken]);

    const user = users[0];
    if (!user) return res.status(401).json({ error: 'Invalid refresh token' });

    const accessToken = jwtUtils.generateAccessToken(user);
    res.json({ accessToken });
  } catch (error) {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
};

const forgotPassword = async (req, res) => {
  const schema = joi.object({
    email: joi.string().email().required(),
  });

  const { error } = schema.validate(req.body);
  if (error) return res.status(400).json({ error: error.details[0].message });

  const { email } = req.body;

  // Check if user exists
  const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
  const user = users[0];
  if (!user) return res.status(404).json({ error: 'User not found' });

  // Generate password reset token
  const resetToken = jwt.sign({ userId: user.id }, process.env.ACCESS_TOKEN, { expiresIn: '30m' });
  const message = `Click the link to reset your password: ${req.protocol}://${req.get('host')}/api/auth/reset-password/${resetToken}`;

  const subject = 'Password Reset';
  await passwordUtils.sendResetPasswordEmail(user.email, subject, message);

  res.json({ message: 'Password reset email sent' });
};

const resetPassword = async (req, res) => {
  const resetToken = req.params.token;
  const newPassword = req.body.password;

  if (!resetToken || !newPassword) return res.status(400).json({ error: 'Missing parameters' });

  try {
    const decoded = jwt.verify(resetToken, process.env.ACCESS_TOKEN);
    const [users] = await pool.execute('SELECT * FROM users WHERE id = ?', [decoded.userId]);
    const user = users[0];

    if (!user) return res.status(404).json({ error: 'User not found' });

    // Hash the new password and update it
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.execute('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, user.id]);

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error(error);
    res.status(401).json({ error: 'Invalid reset token or an error occurred' });
  }
};

module.exports = { register, resetPassword, refreshToken, login, forgotPassword };

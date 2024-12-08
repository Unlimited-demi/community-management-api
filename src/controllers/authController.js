const User = require('../models/User');
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

    
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(409).json({ error: 'Email already exists' });

    
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log(hashedPassword)

    const newUser = new User({ email, password: hashedPassword, role });
    console.log(newUser)
    await newUser.save();

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
   
    const user = await User.findOne({ email }).select('+password');
    if (!user) return res.status(401).json({ error: 'User does not exist' });

    if (user.status !== 'active') return res.status(403).json({ error: 'User is suspended' });

 
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

    
    const accessToken = jwtUtils.generateAccessToken(user);
    const refreshToken = jwtUtils.generateRefreshToken(user);

   
    user.refreshToken = refreshToken;
    await user.save();

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
      const user = await User.findOne({ _id: decoded.userId, refreshToken });
  
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
  
  
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });
  
    
    const resetToken = jwt.sign({ userId: user._id }, process.env.ACCESS_TOKEN, { expiresIn: '30m' });
    const message = `Click the link to reset your password: ${req.protocol}://${req.get('host')}/api/auth/reset-password/${resetToken}`;
   
    const subject = 'Password Reset';
    await passwordUtils.sendResetPasswordEmail(user.email, subject, message );
  
    res.json({ message: 'Password reset email sent' });
  };
  
  const resetPassword = async (req, res) => {
    const resetToken = req.params.token;
    const newPassword = req.body.password;
  
    if (!resetToken || !newPassword) return res.status(400).json({ error: 'Missing parameters' });
  
    try {
      
      const decoded = jwt.verify(resetToken, process.env.ACCESS_TOKEN); 
     
      const user = await User.findOne({ _id: decoded.userId });
  
      if (!user) return res.status(404).json({ error: 'User not found' });
  
      
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedPassword;
  
    
      await user.save();
  
      res.json({ message: 'Password reset successfully' });
    } catch (error) {
      console.error(error);
      res.status(401).json({ error: 'Invalid reset token or an error occurred' });
    }
  };
  module.exports = { register, resetPassword,refreshToken , login, forgotPassword }
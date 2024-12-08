// middleware/roleGuard.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const roleGuard = (allowedRoles) => {
  return async (req, res, next) => {
    const accessToken = req.headers['authorization']?.split(' ')[1];

    if (!accessToken) {
      // If no access token is provided, allow the request to proceed
      return next();
    }

    try {
      const decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN);
      const userRole = decoded.role;

      if (!allowedRoles.includes(userRole)) {
        return res.status(403).json({ error: 'Forbidden' });
      }

      req.user = await User.findById(decoded.userId);
      next();
    } catch (error) {
      res.status(401).json({ error: 'Invalid access token' });
    }
  };
};

module.exports = roleGuard;
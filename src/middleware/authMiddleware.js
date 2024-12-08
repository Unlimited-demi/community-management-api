const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
  const accessToken = req.headers['authorization']?.split(' ')[1];
  if (!accessToken) return res.status(401).json({ error: 'Access token missing' });

  jwt.verify(accessToken, process.env.ACCESS_TOKEN, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

module.exports = authenticateToken;
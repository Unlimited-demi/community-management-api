const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '1syconex.Inc',
  database: 'community',
});

module.exports = pool;

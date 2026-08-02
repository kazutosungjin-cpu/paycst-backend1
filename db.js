require('dotenv').config();
const mysql = require('mysql2/promise');

// A pool, not a single connection — reused across requests, handles
// reconnects, and every query below goes through parameterized `?`
// placeholders so user input is never concatenated into SQL text.
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
});

module.exports = pool;

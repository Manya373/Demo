// db.js
const postgres = require('postgres');

const sql = postgres(process.env.DATABASE_URL, {
  prepare: false, // good for serverless and pooled connections
});

module.exports = sql;

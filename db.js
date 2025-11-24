const postgres = require('postgres');

const sql = postgres(process.env.DATABASE_URL, {
  ssl: 'require',   // <-- THIS FIXES SUPABASE + VERCEL CONNECTION
  prepare: false,
});

module.exports = sql;

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { createDatabasePool } = require('./database');

async function migrate() {
  const pool = createDatabasePool();
  try {
    const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
    await pool.query(schema);
    console.log('Database schema applied successfully.');
  } finally {
    await pool.end();
  }
}

migrate().catch((err) => {
  console.error(`Database migration failed: ${err.message}`);
  process.exitCode = 1;
});

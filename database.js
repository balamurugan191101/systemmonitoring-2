const { Pool } = require('pg');

function createDatabasePool() {
  if (process.env.PGSSL !== 'true') {
    throw new Error('PGSSL must be set to "true"; PostgreSQL TLS is required.');
  }
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');

  let connection;
  try {
    connection = new URL(process.env.DATABASE_URL);
  } catch {
    throw new Error('DATABASE_URL is invalid.');
  }
  if (!['postgres:', 'postgresql:'].includes(connection.protocol)) {
    throw new Error('DATABASE_URL must use the PostgreSQL protocol.');
  }

  // Do not let connection-string SSL parameters override the verified TLS config below.
  for (const option of ['sslmode', 'sslcert', 'sslkey', 'sslrootcert']) {
    connection.searchParams.delete(option);
  }
  return new Pool({
    connectionString: connection.toString(),
    ssl: { rejectUnauthorized: true },
  });
}

module.exports = { createDatabasePool };

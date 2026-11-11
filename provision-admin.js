require('dotenv').config();
const readline = require('readline');
const argon2 = require('argon2');
const { validPassword } = require('./security-policy');
const { createDatabasePool } = require('./database');
const { stdin, stdout } = require('process');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (prompt) => new Promise((resolve) => rl.question(prompt, resolve));
function askHidden(prompt) {
  if (!stdin.isTTY || !stdin.setRawMode) return Promise.reject(new Error('Run this command in an interactive terminal so the password is not echoed.'));
  return new Promise((resolve, reject) => {
    stdout.write(prompt);
    stdin.setRawMode(true); stdin.resume();
    let value = '';
    const finish = (err) => { stdin.setRawMode(false); stdin.pause(); stdin.removeListener('data', onData); stdout.write('\n'); err ? reject(err) : resolve(value); };
    const onData = (buf) => {
      for (const ch of buf.toString('utf8')) {
        if (ch === '\u0003') return finish(new Error('Cancelled'));
        if (ch === '\r' || ch === '\n') return finish();
        if (ch === '\u007f' || ch === '\b') value = value.slice(0, -1);
        else if (ch >= ' ') value += ch;
      }
    };
    stdin.on('data', onData);
  });
}
async function main() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
  const username = (await ask('Super Admin username: ')).trim();
  const email = (await ask('Super Admin email: ')).trim().toLowerCase();
  const password = await askHidden('Password (min 12 chars, upper/lower/number): ');
  if (!/^[A-Za-z0-9_.-]{3,64}$/.test(username) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('Invalid username or email');
  if (!validPassword(password)) throw new Error('Password must be 12–128 characters with upper, lower, and numeric characters');
  const db = createDatabasePool();
  try {
    const exists = await db.query("SELECT 1 FROM users WHERE role='Super Admin' LIMIT 1");
    if (exists.rowCount) throw new Error('A Super Admin already exists; use the approved account-management process.');
    const hash = await argon2.hash(password, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
    const result = await db.query("INSERT INTO users(username,email,password_hash,role) VALUES($1,$2,$3,'Super Admin') RETURNING id", [username, email, hash]);
    await db.query("INSERT INTO audit_logs(user_id,action,details) VALUES($1,'super_admin_provisioned',$2)", [result.rows[0].id, { source: 'command_line' }]);
    console.log(`Created Super Admin ${result.rows[0].id}`);
  } finally { await db.end(); rl.close(); }
}
main().catch((err) => { console.error(err.message); process.exitCode = 1; rl.close(); });

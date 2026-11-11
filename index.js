// Authenticated Storage Monitor API. Monitoring remains file backed; identity,
// access grants, audit records, and sessions are stored in PostgreSQL.
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const argon2 = require('argon2');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ROLES, normalizeLogin, validPassword, mayViewComputer, mayAdministerUsers, mayReviewAudit } = require('./security-policy');
const { readDrives } = require('./drive-info');
const { createDatabasePool } = require('./database');

const PORT = Number(process.env.PORT || 3100);

const HOST = process.env.NODE_ENV === 'production'
  ? '0.0.0.0'
  : (process.env.HOST || '127.0.0.1');

const production = process.env.NODE_ENV === 'production';
const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret || Buffer.byteLength(sessionSecret) < 32) {
  throw new Error('SESSION_SECRET must contain at least 32 bytes');
}
const pool = createDatabasePool();
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', process.env.TRUST_PROXY === 'true' ? 1 : false);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      connectSrc: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      scriptSrc: ["'self'"],
      scriptSrcAttr: ["'none'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
  },
  strictTransportSecurity: production
    ? { maxAge: 31536000 }
    : false,
}));
app.use(express.json({ limit: '16kb' }));
app.use('/api', (_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
app.use((req, res, next) => { res.setTimeout(15000, () => res.status(408).end()); next(); });
app.use(session({
  name: 'storage.sid',
  store: new PgSession({ pool, tableName: 'sessions', createTableIfMissing: true }),
  secret: sessionSecret,
  resave: false, saveUninitialized: false, rolling: true,
  cookie: { httpOnly: true, secure: production, sameSite: 'strict', maxAge: 8 * 60 * 60 * 1000, path: '/' },
}));

const genericLoginError = { error: 'Invalid username/email or password.' };
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false, message: genericLoginError });
const passwordChangeLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many password-change attempts. Try again later.' } });
const adminLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many administrative requests. Try again later.' } });
const dummyPasswordHash = argon2.hash(crypto.randomBytes(32).toString('hex'), { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
const safeUser = ({ id, username, email, role }) => ({ id, username, email, role });

function audit(req, action, details = {}) {
  return pool.query('INSERT INTO audit_logs(user_id, action, details, ip_address) VALUES ($1,$2,$3,$4)',
    [req.session?.user?.id || null, action, details, req.ip]).catch((err) => console.error('Audit write failed:', err.message));
}
function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Authentication required.' });
  pool.query('SELECT id,username,email,role,is_active FROM users WHERE id=$1', [req.session.user.id]).then(({ rows }) => {
    const user = rows[0];
    if (!user || !user.is_active) return req.session.destroy(() => res.status(401).json({ error: 'Authentication required.' }));
    req.session.user = safeUser(user);
    next();
  }).catch(next);
}
function csrf(req, res, next) {
  const origin = req.get('origin');
  const trusted = (process.env.TRUSTED_ORIGINS || '').split(',').map((v) => v.trim()).filter(Boolean);
  if (origin && !trusted.includes(origin) && origin !== `${req.protocol}://${req.get('host')}`) return res.status(403).json({ error: 'Untrusted origin.' });
  if (!req.session.csrfToken || req.get('x-csrf-token') !== req.session.csrfToken) return res.status(403).json({ error: 'Invalid CSRF token.' });
  next();
}
function requireRole(...allowed) {
  return (req, res, next) => allowed.includes(req.session.user.role) ? next() : res.status(403).json({ error: 'Forbidden.' });
}
function canView(req, res, next) {
  const role = req.session.user.role;
  if (!ROLES.includes(role)) return res.status(403).json({ error: 'Forbidden.' });
  if (role === 'Super Admin') return next();
  pool.query('SELECT 1 FROM user_computer_access WHERE user_id=$1 AND computer_id=$2', [req.session.user.id, 'local'])
    .then(({ rowCount }) => mayViewComputer(role, rowCount ? ['local'] : [], 'local') ? next() : res.status(403).json({ error: 'Forbidden.' }))
    .catch(next);
}

app.get('/api/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ status: 'ok' }); }
  catch { res.status(503).json({ status: 'unavailable' }); }
});
app.get('/api/auth/csrf', (req, res) => {
  req.session.csrfToken ||= crypto.randomBytes(32).toString('hex');
  res.set('Cache-Control', 'no-store').json({ csrfToken: req.session.csrfToken });
});
app.post('/api/auth/login', loginLimiter, csrf, async (req, res, next) => {
  try {
    const login = String(req.body?.login || '').trim();
    const password = req.body?.password;
    if (!login || typeof password !== 'string' || password.length > 1024) return res.status(400).json({ error: 'Enter a username/email and password.' });
    const normalized = normalizeLogin(login);
    const { rows } = await pool.query('SELECT id,username,email,password_hash,role,is_active FROM users WHERE lower(username)= $1 OR email=$1 LIMIT 1', [normalized]);
    const user = rows[0];
    let valid = false;
    try { valid = user ? await argon2.verify(user.password_hash, password) : (await argon2.verify(await dummyPasswordHash, password), false); } catch { valid = false; }
    if (!user || !valid || !user.is_active) {
      await audit(req, 'login_failed');
      return res.status(401).json(genericLoginError);
    }
    await new Promise((resolve, reject) => req.session.regenerate((err) => err ? reject(err) : resolve()));
    req.session.cookie.maxAge = req.body?.remember === true ? 30 * 24 * 60 * 60 * 1000 : 8 * 60 * 60 * 1000;
    req.session.user = safeUser(user);
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    await pool.query('UPDATE users SET last_login_at=now() WHERE id=$1', [user.id]);
    await audit(req, 'login_success');
    res.set('Cache-Control', 'no-store').json({ user: safeUser(user), csrfToken: req.session.csrfToken });
  } catch (err) { next(err); }
});
app.get('/api/auth/me', (req, res, next) => {
  if (!req.session.user) return res.set('Cache-Control', 'no-store').json({ user: null });
  requireAuth(req, res, next);
}, (req, res) => res.set('Cache-Control', 'no-store').json({ user: req.session.user }));
app.post('/api/auth/logout', requireAuth, csrf, async (req, res, next) => {
  try {
    await audit(req, 'logout');
    req.session.destroy((err) => { if (err) return next(err); res.clearCookie('storage.sid', { httpOnly: true, secure: production, sameSite: 'strict', path: '/' }); res.status(204).end(); });
  } catch (err) { next(err); }
});
app.post('/api/auth/change-password', passwordChangeLimiter, requireAuth, csrf, async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!validPassword(newPassword)) return res.status(400).json({ error: 'Use 12–128 characters with upper, lower, and numeric characters.' });
    const { rows } = await pool.query('SELECT password_hash FROM users WHERE id=$1 AND is_active=true', [req.session.user.id]);
    if (!rows[0] || !(await argon2.verify(rows[0].password_hash, String(currentPassword || '')))) return res.status(400).json({ error: 'Current password is incorrect.' });
    const hash = await argon2.hash(newPassword, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
    await pool.query('UPDATE users SET password_hash=$1,updated_at=now() WHERE id=$2', [hash, req.session.user.id]);
    await audit(req, 'password_changed');
    await pool.query("DELETE FROM sessions WHERE sess->'user'->>'id'=$1", [req.session.user.id]);
    res.clearCookie('storage.sid', { httpOnly: true, secure: production, sameSite: 'strict', path: '/' });
    res.status(204).end();
  } catch (err) { next(err); }
});

app.get('/api/admin/users', adminLimiter, requireAuth, requireRole('Super Admin'), async (_req, res, next) => {
  try { const { rows } = await pool.query('SELECT id,username,email,role,is_active,created_at,updated_at,last_login_at FROM users ORDER BY username'); res.json(rows); }
  catch (err) { next(err); }
});
app.post('/api/admin/users', adminLimiter, requireAuth, requireRole('Super Admin'), csrf, async (req, res, next) => {
  try {
    const { username, email, password, role } = req.body || {};
    const cleanName = String(username || '').trim(), cleanEmail = normalizeLogin(email);
    if (!/^[A-Za-z0-9_.-]{3,64}$/.test(cleanName) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail) || !validPassword(password) || !ROLES.includes(role)) return res.status(400).json({ error: 'Invalid account details.' });
    const hash = await argon2.hash(password, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
    const { rows } = await pool.query('INSERT INTO users(username,email,password_hash,role) VALUES($1,$2,$3,$4) RETURNING id,username,email,role,is_active,created_at', [cleanName, cleanEmail, hash, role]);
    await audit(req, 'user_created', { targetUserId: rows[0].id, role });
    res.status(201).json(rows[0]);
  } catch (err) { if (err.code === '23505') return res.status(409).json({ error: 'Username or email is already in use.' }); next(err); }
});
app.patch('/api/admin/users/:id', adminLimiter, requireAuth, requireRole('Super Admin'), csrf, async (req, res, next) => {
  const db = await pool.connect();
  try {
    const id = String(req.params.id);
    const { role, is_active: isActive } = req.body || {};
    if (id === req.session.user.id && (role !== undefined || isActive === false)) return res.status(400).json({ error: 'You cannot change your own role or disable your account.' });
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) return res.status(400).json({ error: 'Invalid user ID.' });
    if (role !== undefined && !ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role.' });
    if (isActive !== undefined && typeof isActive !== 'boolean') return res.status(400).json({ error: 'is_active must be boolean.' });
    await db.query('BEGIN');
    await db.query('SELECT pg_advisory_xact_lock($1)', [781923]);
    const before = await db.query('SELECT role,is_active FROM users WHERE id=$1 FOR UPDATE', [id]);
    if (!before.rowCount) { await db.query('ROLLBACK'); return res.status(404).json({ error: 'User not found.' }); }
    if (before.rows[0].role === 'Super Admin' && ((role && role !== 'Super Admin') || isActive === false)) {
      const admins = await db.query("SELECT count(*)::int AS count FROM users WHERE role='Super Admin' AND is_active=true");
      if (admins.rows[0].count <= 1) { await db.query('ROLLBACK'); return res.status(400).json({ error: 'At least one active Super Admin must remain.' }); }
    }
    const updated = await db.query('UPDATE users SET role=COALESCE($1,role),is_active=COALESCE($2,is_active),updated_at=now() WHERE id=$3 RETURNING id,username,email,role,is_active,updated_at', [role ?? null, isActive ?? null, id]);
    if (role !== undefined || isActive !== undefined) {
      await db.query("DELETE FROM sessions WHERE sess->'user'->>'id'=$1", [id]);
    }
    await db.query('COMMIT');
    if (role !== undefined || isActive !== undefined) await audit(req, role !== undefined && role !== before.rows[0].role ? 'role_changed' : 'account_status_changed', { targetUserId: id, role: updated.rows[0].role, isActive: updated.rows[0].is_active });
    res.json(updated.rows[0]);
  } catch (err) { try { await db.query('ROLLBACK'); } catch { } next(err); }
  finally { db.release(); }
});
app.get('/api/admin/audit', adminLimiter, requireAuth, requireRole('Super Admin'), async (_req, res, next) => {
  try { const { rows } = await pool.query('SELECT id,user_id,action,details,ip_address,created_at FROM audit_logs ORDER BY created_at DESC LIMIT 200'); res.json(rows); }
  catch (err) { next(err); }
});
app.get('/api/admin/computers', adminLimiter, requireAuth, async (req, res, next) => {
  try {
    const sql = req.session.user.role === 'Super Admin'
      ? 'SELECT id,display_name,monitoring_status,metadata,created_at,updated_at FROM monitored_computers ORDER BY display_name'
      : 'SELECT c.id,c.display_name,c.monitoring_status,c.metadata,c.created_at,c.updated_at FROM monitored_computers c JOIN user_computer_access a ON a.computer_id=c.id WHERE a.user_id=$1 ORDER BY c.display_name';
    const { rows } = await pool.query(sql, req.session.user.role === 'Super Admin' ? [] : [req.session.user.id]);
    res.json(rows);
  } catch (err) { next(err); }
});
app.post('/api/admin/computers', adminLimiter, requireAuth, requireRole('Super Admin'), csrf, async (req, res, next) => {
  try {
    const { id, display_name: displayName, metadata } = req.body || {};
    if (typeof id !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(id) || typeof displayName !== 'string' || !displayName.trim() || displayName.length > 128 || (metadata !== undefined && (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)))) return res.status(400).json({ error: 'Invalid computer details.' });
    const { rows } = await pool.query('INSERT INTO monitored_computers(id,display_name,metadata) VALUES($1,$2,$3) RETURNING id,display_name,monitoring_status,metadata,created_at', [id, displayName.trim(), metadata || {}]);
    await audit(req, 'computer_registered', { computerId: id });
    res.status(201).json(rows[0]);
  } catch (err) { if (err.code === '23505') return res.status(409).json({ error: 'Computer is already registered.' }); next(err); }
});
app.patch('/api/admin/computers/:id', adminLimiter, requireAuth, requireRole('Super Admin', 'Admin'), csrf, async (req, res, next) => {
  try {
    const { display_name: displayName, metadata } = req.body || {};
    if ((displayName === undefined && metadata === undefined) || (displayName !== undefined && (typeof displayName !== 'string' || !displayName.trim() || displayName.length > 128)) || (metadata !== undefined && (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)))) return res.status(400).json({ error: 'Invalid computer update.' });
    const id = req.params.id;
    const isSuperAdmin = req.session.user.role === 'Super Admin';
    const sql = isSuperAdmin
      ? 'UPDATE monitored_computers SET display_name=COALESCE($1,display_name),metadata=COALESCE($2,metadata),updated_at=now() WHERE id=$3 RETURNING id,display_name,monitoring_status,metadata,updated_at'
      : 'UPDATE monitored_computers c SET display_name=COALESCE($1,c.display_name),metadata=COALESCE($2,c.metadata),updated_at=now() WHERE c.id=$3 AND EXISTS(SELECT 1 FROM user_computer_access a WHERE a.user_id=$4 AND a.computer_id=c.id) RETURNING c.id,c.display_name,c.monitoring_status,c.metadata,c.updated_at';
    const params = isSuperAdmin ? [displayName?.trim() ?? null, metadata ?? null, id] : [displayName?.trim() ?? null, metadata ?? null, id, req.session.user.id];
    const { rows } = await pool.query(sql, params);
    if (!rows[0]) return res.status(404).json({ error: 'Computer not found.' });
    await audit(req, 'computer_updated', { computerId: id });
    res.json(rows[0]);
  } catch (err) { next(err); }
});
app.put('/api/admin/computers/:id/access/:userId', adminLimiter, requireAuth, requireRole('Super Admin'), csrf, async (req, res, next) => {
  try {
    const { id, userId } = req.params;
    if (!/^[A-Za-z0-9._-]{1,128}$/.test(id) || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(userId)) return res.status(400).json({ error: 'Invalid computer or user ID.' });
    await pool.query('INSERT INTO user_computer_access(user_id,computer_id) VALUES($1,$2) ON CONFLICT DO NOTHING', [userId, id]);
    await audit(req, 'computer_access_granted', { computerId: id, targetUserId: userId });
    res.status(204).end();
  } catch (err) { if (err.code === '23503') return res.status(404).json({ error: 'User or computer not found.' }); next(err); }
});
app.delete('/api/admin/computers/:id/access/:userId', adminLimiter, requireAuth, requireRole('Super Admin'), csrf, async (req, res, next) => {
  try {
    if (!/^[A-Za-z0-9._-]{1,128}$/.test(req.params.id) || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(req.params.userId)) return res.status(400).json({ error: 'Invalid computer or user ID.' });
    await pool.query('DELETE FROM user_computer_access WHERE user_id=$1 AND computer_id=$2', [req.params.userId, req.params.id]);
    await audit(req, 'computer_access_revoked', { computerId: req.params.id, targetUserId: req.params.userId });
    res.status(204).end();
  } catch (err) { next(err); }
});

function validatedAbsolutePath(value, variableName) {
  if (!value) return null;
  const candidate = value.trim();
  const components = candidate.split(/[\\/]+/);
  if (!path.isAbsolute(candidate) || candidate.includes('\0') || components.includes('..')) {
    console.warn(`${variableName} must be absolute and contain no parent-directory components; ignoring it.`);
    return null;
  }
  return path.resolve(candidate);
}

function resolveLogFile() {
  const explicit = validatedAbsolutePath(process.env.LOG_FILE, 'LOG_FILE');
  if (explicit) return explicit;
  const configuredDir = validatedAbsolutePath(process.env.STORAGE_MONITOR_LOG_DIR, 'STORAGE_MONITOR_LOG_DIR');
  if (configuredDir) return path.join(configuredDir, 'storage_events.jsonl');
  const home = process.env.LOCALAPPDATA || process.env.USERPROFILE || require('os').homedir();
  const candidates = [
    configuredDir && path.join(configuredDir, 'storage_events.jsonl'),
    process.env.PROGRAMDATA && path.join(process.env.PROGRAMDATA, 'StorageMonitor', 'storage_events.jsonl'),
    path.join(home, 'StorageMonitor', 'storage_events.jsonl'),
    path.join(home, 'AppData', 'Local', 'StorageMonitor', 'storage_events.jsonl'),
  ].filter(Boolean);
  const existing = candidates.flatMap((candidate) => {
    try { const stat = fs.statSync(candidate); return stat.isFile() ? [{ candidate, mtime: stat.mtimeMs }] : []; }
    catch { return []; }
  });
  existing.sort((a, b) => b.mtime - a.mtime);
  return existing[0]?.candidate || candidates[0] || path.join(__dirname, 'storage_events.jsonl');
}
const MAX_EVENTS = 1000;
const MAX_EVENT_LINE_CHARS = 64 * 1024;
const MAX_LOG_SCAN_BYTES = 8 * 1024 * 1024;
const IGNORED_EVENT_SUFFIXES = ['.tmp', '.bak', '.swp', '.zstmp', '.crdownload', '.part', '.partial', '.lnk'];

function parseEventLine(line) {
  if (!line.trim()) return null;
  try {
    const event = JSON.parse(line);
    if (!event || typeof event !== 'object' || Array.isArray(event)) return null;
    const components = [event.file_name, event.subfolder, event.full_path]
      .filter(Boolean)
      .flatMap((value) => String(value).split(/[\\/]/));
    const ignored = components.some((name) => {
      const lowerName = name.toLowerCase();
      return name.startsWith('~$') || name.startsWith('.~') || IGNORED_EVENT_SUFFIXES.some((suffix) => lowerName.endsWith(suffix));
    });
    return ignored ? null : event;
  } catch { return null; }
}

async function readEvents() {
  const file = resolveLogFile();
  let size;
  try { size = fs.statSync(file).size; }
  catch (err) { if (err.code === 'ENOENT') return []; throw err; }
  if (size === 0) return [];

  const start = Math.max(0, size - MAX_LOG_SCAN_BYTES);
  const stream = fs.createReadStream(file, { encoding: 'utf8', highWaterMark: 64 * 1024, start, end: size - 1 });
  const events = [];
  let next = 0;
  let line = '';
  let discarding = start > 0;

  function append(part) {
    if (discarding) return;
    if (line.length + part.length > MAX_EVENT_LINE_CHARS) { line = ''; discarding = true; return; }
    line += part;
  }
  function saveLine() {
    if (!discarding) {
      const event = parseEventLine(line);
      if (event) {
        if (events.length < MAX_EVENTS) events.push(event);
        else { events[next] = event; next = (next + 1) % MAX_EVENTS; }
      }
    }
    line = '';
    discarding = false;
  }

  for await (const chunk of stream) {
    let offset = 0;
    while (offset < chunk.length) {
      const newline = chunk.indexOf('\n', offset);
      if (newline === -1) { append(chunk.slice(offset)); break; }
      append(chunk.slice(offset, newline));
      saveLine();
      offset = newline + 1;
    }
  }
  if (!discarding && line) {
    const event = parseEventLine(line);
    if (event) {
      if (events.length < MAX_EVENTS) events.push(event);
      else { events[next] = event; next = (next + 1) % MAX_EVENTS; }
    }
  }
  return events.length < MAX_EVENTS ? events : [...events.slice(next), ...events.slice(0, next)];
}
app.get('/api/files', requireAuth, canView, async (_req, res, next) => {
  try { res.set('Cache-Control', 'no-store').json(await readEvents()); }
  catch (err) { next(err); }
});
app.get('/api/drives', requireAuth, canView, (_req, res) => res.set('Cache-Control', 'no-store').json(readDrives()));
app.use((req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((err, _req, res, _next) => { console.error('API request failed:', err.message); res.status(500).json({ error: 'Internal server error.' }); });

let server;

pool.query('SELECT 1')
  .then(() => {
    server = app.listen(PORT, HOST, () =>
      console.log(`Storage Monitor API listening on ${HOST}:${PORT}`)
    );
  })
  .catch((err) => {
    console.error('Database connection failed:', err.message);
    process.exitCode = 1;
  });
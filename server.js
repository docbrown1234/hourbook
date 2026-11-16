'use strict';
// Hourbook server: logins, role-based access and a small document store on Postgres.
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const PROD = process.env.NODE_ENV === 'production';
if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set. In Render, copy the database\'s Internal Database URL into this service\'s Environment as DATABASE_URL.');
  process.exit(1);
}
const PORT = process.env.PORT || 10000;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : false,
  max: 5,
});
const q = (text, values) => pool.query(text, values);
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const newToken = () => crypto.randomBytes(32).toString('base64url');

const COLLS = new Set(['employees', 'projects', 'consultants', 'invoices', 'timers', 'settings', 'entries', 'expenses', 'cbills']);
const DATED = new Set(['entries', 'expenses', 'cbills']);
const ID_RE = /^[A-Za-z0-9_~.-]{1,100}$/;
const FIELD_RE = /^[A-Za-z0-9_]{1,40}$/;
const USERNAME_RE = /^[A-Za-z0-9._@-]{2,60}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/* ---------------- schema ---------------- */
async function migrate() {
  await q(`
    create table if not exists users(
      id serial primary key,
      username text not null,
      name text not null default '',
      role text not null default 'staff' check (role in ('admin','staff')),
      employee_id text,
      password_hash text,
      active boolean not null default true,
      setup_hash text,
      setup_expires timestamptz,
      created_at timestamptz not null default now());
    create unique index if not exists users_username on users (lower(username));
    create table if not exists sessions(
      token_hash text primary key,
      user_id int not null references users(id) on delete cascade,
      expires_at timestamptz not null);
    create table if not exists docs(
      coll text not null,
      id text not null,
      data jsonb not null,
      updated_at timestamptz not null default now(),
      updated_by int,
      primary key (coll, id));
    create index if not exists docs_month on docs (coll, (data->>'month'));
  `);
}

async function bootstrapAdmin() {
  const { rows } = await q('select count(*)::int as n from users');
  if (rows[0].n > 0) return;
  const username = process.env.ADMIN_USERNAME || 'admin';
  let token = process.env.ADMIN_SETUP_TOKEN;
  const generated = !token;
  if (generated) token = newToken();
  await q(
    `insert into users (username, name, role, setup_hash, setup_expires)
     values ($1, 'Administrator', 'admin', $2, now() + interval '14 days')`,
    [username, sha(token)]
  );
  console.log(`Created admin login "${username}".` +
    (generated ? ` One-time setup link: ${process.env.PUBLIC_URL || ''}/setup?token=${token}` : ' Use the setup link built from ADMIN_SETUP_TOKEN.'));
}

/* ---------------- app & middleware ---------------- */
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src https://fonts.gstatic.com",
  "img-src 'self' data: blob:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join('; ');
app.use((req, res, next) => {
  res.set({
    'Content-Security-Policy': CSP,
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin',
  });
  if (PROD) res.set('Strict-Transport-Security', 'max-age=31536000');
  next();
});
app.use(express.json({ limit: '300kb' }));

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function readCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i > 0) { try { out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch {} }
  });
  return out;
}
function setSessionCookie(res, value, maxAgeSec) {
  res.append('Set-Cookie', `hb_sess=${value}; Path=/; HttpOnly; SameSite=Lax${PROD ? '; Secure' : ''}; Max-Age=${maxAgeSec}`);
}
async function startSession(res, userId) {
  const token = newToken();
  await q(`insert into sessions (token_hash, user_id, expires_at) values ($1, $2, now() + interval '30 days')`, [sha(token), userId]);
  await q('delete from sessions where expires_at < now()');
  setSessionCookie(res, token, 30 * 86400);
}

// Writes must carry a custom header, which a cross-site form cannot send.
app.use('/api', (req, res, next) => {
  if (req.method !== 'GET' && req.get('X-Hourbook') !== '1') return res.status(403).json({ error: 'Bad request.' });
  next();
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

const requireUser = wrap(async (req, res, next) => {
  const token = readCookies(req).hb_sess;
  if (!token) return res.status(401).json({ error: 'Sign in required.' });
  const { rows } = await q(
    `select u.* from sessions s join users u on u.id = s.user_id
     where s.token_hash = $1 and s.expires_at > now() and u.active`, [sha(token)]);
  if (!rows[0]) return res.status(401).json({ error: 'Sign in required.' });
  req.user = rows[0];
  next();
});
const requireAdmin = (req, res, next) => (req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Only admins can do that.' }));

/* ---------------- auth ---------------- */
const attempts = new Map();
function isLimited(key) {
  const now = Date.now();
  const list = (attempts.get(key) || []).filter((t) => now - t < 15 * 60e3);
  attempts.set(key, list);
  return list.length >= 10;
}

app.post('/api/login', wrap(async (req, res) => {
  const username = String((req.body || {}).username || '').trim();
  const password = String((req.body || {}).password || '');
  const key = `${req.ip}|${username.toLowerCase()}`;
  if (isLimited(key)) return res.status(429).json({ error: 'Too many attempts. Wait 15 minutes and try again.' });
  const { rows } = await q('select * from users where lower(username) = lower($1) and active', [username]);
  const user = rows[0];
  const ok = !!(user && user.password_hash && await bcrypt.compare(password, user.password_hash));
  if (!ok) {
    attempts.get(key).push(Date.now());
    return res.status(401).json({ error: 'That username and password don’t match.' });
  }
  await startSession(res, user.id);
  res.json({ ok: true });
}));

app.post('/api/logout', wrap(async (req, res) => {
  const token = readCookies(req).hb_sess;
  if (token) await q('delete from sessions where token_hash = $1', [sha(token)]);
  setSessionCookie(res, '', 0);
  res.json({ ok: true });
}));

const publicUser = (u) => ({
  id: u.id, username: u.username, name: u.name, role: u.role, employeeId: u.employee_id, active: u.active,
  hasPassword: !!u.password_hash,
  setupPending: !!u.setup_hash && new Date(u.setup_expires) > new Date(),
});

app.get('/api/me', requireUser, (req, res) => res.json(publicUser(req.user)));

app.get('/api/setup/:token', wrap(async (req, res) => {
  const { rows } = await q('select * from users where setup_hash = $1 and setup_expires > now() and active', [sha(req.params.token)]);
  if (!rows[0]) return res.status(404).json({ error: 'This setup link has expired or was already used. Ask your admin for a new one.' });
  res.json({ username: rows[0].username, name: rows[0].name });
}));

app.post('/api/setup', wrap(async (req, res) => {
  const token = String((req.body || {}).token || '');
  const password = String((req.body || {}).password || '');
  if (password.length < 10 || password.length > 200) return res.status(400).json({ error: 'Use at least 10 characters.' });
  const { rows } = await q('select * from users where setup_hash = $1 and setup_expires > now() and active', [sha(token)]);
  const user = rows[0];
  if (!user) return res.status(404).json({ error: 'This setup link has expired or was already used. Ask your admin for a new one.' });
  const hash = await bcrypt.hash(password, 12);
  await q('update users set password_hash = $1, setup_hash = null, setup_expires = null where id = $2', [hash, user.id]);
  await q('delete from sessions where user_id = $1', [user.id]);
  await startSession(res, user.id);
  res.json({ ok: true });
}));

/* ---------------- users (admin) ---------------- */
async function issueSetupLink(userId) {
  const token = newToken();
  await q(`update users set setup_hash = $1, setup_expires = now() + interval '7 days' where id = $2`, [sha(token), userId]);
  return token;
}
async function otherActiveAdmins(userId) {
  const { rows } = await q(`select count(*)::int as n from users where role = 'admin' and active and id <> $1`, [userId]);
  return rows[0].n;
}

app.get('/api/users', requireUser, requireAdmin, wrap(async (req, res) => {
  const { rows } = await q('select * from users order by active desc, lower(username)');
  res.json(rows.map(publicUser));
}));

app.post('/api/users', requireUser, requireAdmin, wrap(async (req, res) => {
  const b = req.body || {};
  const username = String(b.username || '').trim();
  if (!USERNAME_RE.test(username)) return res.status(400).json({ error: 'Usernames are 2–60 letters, numbers, dots, dashes or @.' });
  const role = b.role === 'admin' ? 'admin' : 'staff';
  const employeeId = b.employeeId && ID_RE.test(b.employeeId) ? b.employeeId : null;
  try {
    const { rows } = await q('insert into users (username, name, role, employee_id) values ($1, $2, $3, $4) returning *',
      [username, String(b.name || '').slice(0, 100), role, employeeId]);
    const token = await issueSetupLink(rows[0].id);
    res.json({ user: publicUser(rows[0]), setupToken: token });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'That username is already taken.' });
    throw e;
  }
}));

app.patch('/api/users/:id', requireUser, requireAdmin, wrap(async (req, res) => {
  const id = Number(req.params.id);
  const { rows } = await q('select * from users where id = $1', [id]);
  const user = rows[0];
  if (!user) return res.status(404).json({ error: 'No such login.' });
  const b = req.body || {};
  const next = {
    name: b.name !== undefined ? String(b.name).slice(0, 100) : user.name,
    role: b.role !== undefined ? (b.role === 'admin' ? 'admin' : 'staff') : user.role,
    employee_id: b.employeeId !== undefined ? (b.employeeId && ID_RE.test(b.employeeId) ? b.employeeId : null) : user.employee_id,
    active: b.active !== undefined ? !!b.active : user.active,
  };
  const losingAdmin = user.role === 'admin' && user.active && (next.role !== 'admin' || !next.active);
  if (losingAdmin && (await otherActiveAdmins(id)) === 0) return res.status(400).json({ error: 'Keep at least one active admin.' });
  const upd = await q('update users set name = $1, role = $2, employee_id = $3, active = $4 where id = $5 returning *',
    [next.name, next.role, next.employee_id, next.active, id]);
  if (!next.active) await q('delete from sessions where user_id = $1', [id]);
  res.json(publicUser(upd.rows[0]));
}));

app.post('/api/users/:id/setup-link', requireUser, requireAdmin, wrap(async (req, res) => {
  const id = Number(req.params.id);
  const { rows } = await q('select * from users where id = $1 and active', [id]);
  if (!rows[0]) return res.status(404).json({ error: 'No such active login.' });
  res.json({ setupToken: await issueSetupLink(id) });
}));

/* ---------------- documents ---------------- */
// Staff see only what they need to log their own time and expenses.
const STAFF_VIEW = {
  employees: (d) => ({ name: d.name, title: d.title, active: d.active }),
  projects: (d) => ({ name: d.name, client: d.client, code: d.code, active: d.active, billable: d.billable }),
  settings: (d) => ({ company: d.company }),
};
function viewFor(user, coll, id, data) {
  if (user.role === 'admin') return data;
  if (coll === 'invoices' || coll === 'cbills') return null;
  if (coll === 'timers') return user.employee_id && id === user.employee_id ? data : null;
  if (coll === 'entries' || coll === 'expenses') return user.employee_id && data.empId === user.employee_id ? data : null;
  if (STAFF_VIEW[coll]) return STAFF_VIEW[coll](data);
  return data; // consultants: names only
}
function staffMayWrite(user, coll, id, oldData, newData) {
  if (!user.employee_id) return false;
  if (coll === 'timers') return id === user.employee_id;
  if (coll === 'entries' || coll === 'expenses') {
    if (oldData && oldData.empId !== user.employee_id) return false;
    if (newData && newData.empId !== user.employee_id) return false;
    return true;
  }
  return false;
}
async function isLocked(coll, oldData, newData) {
  if (!DATED.has(coll)) return false;
  for (const d of [oldData, newData]) {
    if (!d || !d.projectId || !d.month) continue;
    const { rows } = await q(`select 1 from docs where coll = 'invoices' and id = $1 and data->>'status' = 'invoiced'`, [`${d.projectId}_${d.month}`]);
    if (rows[0]) return true;
  }
  return false;
}
function validate(coll, data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return 'Expected an object.';
  if (DATED.has(coll)) {
    if (!DATE_RE.test(String(data.date || ''))) return 'Each entry needs a date.';
    data.month = data.date.slice(0, 7);
    if (!data.projectId) return 'Each entry needs a project.';
  }
  if (coll === 'entries') {
    const h = Number(data.hours);
    if (!(h > 0 && h <= 24)) return 'Hours must be between 0 and 24.';
  }
  if ((coll === 'expenses' || coll === 'cbills') && !Number.isFinite(Number(data.amount))) return 'Enter the cost as a number.';
  return null;
}
function checkParams(req, res) {
  const { coll, id } = req.params;
  if (!COLLS.has(coll)) { res.status(404).json({ error: 'Not found.' }); return false; }
  if (id !== undefined && !ID_RE.test(id)) { res.status(400).json({ error: 'Bad id.' }); return false; }
  return true;
}
async function getDoc(coll, id) {
  const { rows } = await q('select data from docs where coll = $1 and id = $2', [coll, id]);
  return rows[0] ? rows[0].data : null;
}

app.get('/api/c/:coll', requireUser, wrap(async (req, res) => {
  if (!checkParams(req, res)) return;
  const where = ['coll = $1'];
  const values = [req.params.coll];
  for (const [k, v] of Object.entries(req.query)) {
    if (!FIELD_RE.test(k) || typeof v !== 'string') return res.status(400).json({ error: 'Bad filter.' });
    values.push(k, v);
    where.push(`data->>$${values.length - 1} = $${values.length}`);
  }
  const { rows } = await q(`select id, data from docs where ${where.join(' and ')} limit 5000`, values);
  const out = [];
  for (const r of rows) {
    const data = viewFor(req.user, req.params.coll, r.id, r.data);
    if (data) out.push({ id: r.id, data });
  }
  res.json(out);
}));

app.get('/api/c/:coll/:id', requireUser, wrap(async (req, res) => {
  if (!checkParams(req, res)) return;
  const data = await getDoc(req.params.coll, req.params.id);
  const view = data && viewFor(req.user, req.params.coll, req.params.id, data);
  res.json(view ? { id: req.params.id, data: view } : null);
}));

async function writeDoc(req, res, mode) {
  if (!checkParams(req, res)) return;
  const { coll, id } = req.params;
  const oldData = await getDoc(coll, id);
  let newData = null;
  if (mode !== 'delete') {
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) return res.status(400).json({ error: 'Expected an object.' });
    newData = mode === 'merge' ? { ...(oldData || {}), ...body } : { ...body };
    const problem = validate(coll, newData);
    if (problem) return res.status(400).json({ error: problem });
  }
  if (req.user.role !== 'admin' && !staffMayWrite(req.user, coll, id, oldData, newData)) {
    return res.status(403).json({ error: 'You can only change your own time and expenses.' });
  }
  if (await isLocked(coll, oldData, newData)) {
    return res.status(409).json({ error: 'That month is invoiced for this project. Move the invoice back to draft to change it.' });
  }
  if (mode === 'delete') {
    await q('delete from docs where coll = $1 and id = $2', [coll, id]);
  } else {
    await q(`insert into docs (coll, id, data, updated_by) values ($1, $2, $3, $4)
             on conflict (coll, id) do update set data = excluded.data, updated_at = now(), updated_by = excluded.updated_by`,
      [coll, id, newData, req.user.id]);
  }
  res.status(204).end();
}
app.put('/api/c/:coll/:id', requireUser, wrap((req, res) => writeDoc(req, res, 'set')));
app.patch('/api/c/:coll/:id', requireUser, wrap((req, res) => writeDoc(req, res, 'merge')));
app.delete('/api/c/:coll/:id', requireUser, wrap((req, res) => writeDoc(req, res, 'delete')));

/* ---------------- page ---------------- */
const INDEX = path.join(__dirname, 'public', 'index.html');
app.get(['/', '/setup'], (req, res) => { res.set('Cache-Control', 'no-cache'); res.sendFile(INDEX); });
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((req, res) => res.redirect('/'));
app.use((err, req, res, next) => {
  console.error(err);
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'That request is too large.' });
  res.status(500).json({ error: 'Something went wrong on the server. Try again.' });
});

(async () => {
  await migrate();
  await bootstrapAdmin();
  app.listen(PORT, () => console.log(`Hourbook listening on ${PORT}`));
})().catch((e) => { console.error(e); process.exit(1); });

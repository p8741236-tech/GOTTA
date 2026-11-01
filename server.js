// Servidor de Gotta: cuentas reales (correo + contraseña), sesiones y sincronización del progreso.
// Sin dependencias: solo Node >= 22.13 (node:sqlite, node:crypto, node:http).
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const scrypt = promisify(crypto.scrypt);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = +process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_BODY = 3 * 1024 * 1024;
const DATA_KEYS = ['arc-p', 'arc-b', 'gotta-recent', 'gotta-ach'];

fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'gotta.db'));
db.exec(`
PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
  avatar TEXT NOT NULL, color TEXT NOT NULL, bio TEXT NOT NULL DEFAULT '',
  pw TEXT NOT NULL, data TEXT NOT NULL DEFAULT '{}', rev INTEGER NOT NULL DEFAULT 0,
  created INTEGER NOT NULL, updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created INTEGER NOT NULL, last_seen INTEGER NOT NULL, ua TEXT);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);`);

const q = {
  userByEmail: db.prepare('SELECT * FROM users WHERE email=?'),
  userById: db.prepare('SELECT * FROM users WHERE id=?'),
  insUser: db.prepare('INSERT INTO users(email,name,avatar,color,pw,data,rev,created,updated) VALUES(?,?,?,?,?,?,1,?,?)'),
  insSess: db.prepare('INSERT INTO sessions(token_hash,user_id,created,last_seen,ua) VALUES(?,?,?,?,?)'),
  sess: db.prepare('SELECT s.token_hash,s.last_seen,u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?'),
  touch: db.prepare('UPDATE sessions SET last_seen=? WHERE token_hash=?'),
  delSess: db.prepare('DELETE FROM sessions WHERE token_hash=?'),
  delOthers: db.prepare('DELETE FROM sessions WHERE user_id=? AND token_hash<>?'),
  trimSess: db.prepare('DELETE FROM sessions WHERE user_id=? AND token_hash NOT IN (SELECT token_hash FROM sessions WHERE user_id=? ORDER BY last_seen DESC LIMIT 500)'),
  setData: db.prepare('UPDATE users SET data=?,rev=rev+1,updated=? WHERE id=? AND rev=?'),
  setProfile: db.prepare('UPDATE users SET avatar=?,color=?,bio=?,updated=? WHERE id=?'),
  setPw: db.prepare('UPDATE users SET pw=?,updated=? WHERE id=?'),
  delUser: db.prepare('DELETE FROM users WHERE id=?'),
};
const tx = fn => { db.exec('BEGIN IMMEDIATE'); try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; } };

/* ---------- utilidades ---------- */
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
async function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  const h = await scrypt(pw, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 96 * 1024 * 1024 });
  return `scrypt$32768$8$1$${salt.toString('base64')}$${h.toString('base64')}`;
}
async function checkPw(pw, stored) {
  const [alg, N, r, p, s, h] = String(stored).split('$');
  if (alg !== 'scrypt') return false;
  const want = Buffer.from(h, 'base64');
  const got = await scrypt(pw, Buffer.from(s, 'base64'), want.length, { N: +N, r: +r, p: +p, maxmem: 96 * 1024 * 1024 });
  return crypto.timingSafeEqual(got, want);
}
const DUMMY = hashPw('dummy-password-for-timing'); // iguala el tiempo cuando el correo no existe
const EMAIL_RX = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;
const NAME_RX = /^[\p{L}\p{N}_.\- ]{3,20}$/u;
const COLOR_RX = /^#[0-9a-fA-F]{6}$/;
const cleanAvatar = a => (typeof a === 'string' && a.length >= 1 && a.length <= 16 ? a : '👤');
const cleanColor = c => (typeof c === 'string' && COLOR_RX.test(c) ? c : '#ff6a00');
const cleanBio = b => (typeof b === 'string' ? b.trim().slice(0, 60) : '');

function cleanData(d) {
  if (!d || typeof d !== 'object' || Array.isArray(d)) return null;
  const out = {}; let total = 0;
  for (const k of DATA_KEYS) {
    const v = d[k];
    if (v == null) continue;
    if (typeof v !== 'string' || v.length > 1.5e6) return null;
    try { JSON.parse(v); } catch { return null; }
    total += v.length; out[k] = v;
  }
  return total <= 2e6 ? out : null;
}
const publicUser = u => ({ email: u.email, name: u.name, avatar: u.avatar, color: u.color, bio: u.bio, created: u.created, rev: u.rev, data: JSON.parse(u.data || '{}') });

/* ---------- límite de intentos ---------- */
const hits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now(); let e = hits.get(key);
  if (!e || e.reset < now) e = { n: 0, reset: now + windowMs };
  e.n++; hits.set(key, e);
  return e.n > max;
}
setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (v.reset < n) hits.delete(k); }, 10 * 60 * 1000).unref();

/* ---------- HTTP ---------- */
class HttpErr extends Error { constructor(status, msg, extra) { super(msg); this.status = status; this.extra = extra; } }
const ip = req => (TRUST_PROXY ? String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() : '') || req.socket.remoteAddress || '?';
function send(res, status, obj, headers = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on('data', c => { n += c.length; if (n > MAX_BODY) { reject(new HttpErr(413, 'Datos demasiado grandes.')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch { reject(new HttpErr(400, 'JSON no válido.')); } });
    req.on('error', reject);
  });
}
function authed(req) {
  const m = /^Bearer ([A-Za-z0-9_-]{20,100})$/.exec(req.headers.authorization || '');
  if (!m) throw new HttpErr(401, 'Sesión no válida. Inicia sesión de nuevo.');
  const th = sha(m[1]); const row = q.sess.get(th);
  if (!row) throw new HttpErr(401, 'Sesión cerrada. Inicia sesión de nuevo.');
  if (Date.now() - row.last_seen > 36e5) q.touch.run(Date.now(), th);
  return { th, user: row };
}
function newSession(userId, req) {
  const token = crypto.randomBytes(32).toString('base64url');
  q.insSess.run(sha(token), userId, Date.now(), Date.now(), String(req.headers['user-agent'] || '').slice(0, 200));
  q.trimSess.run(userId, userId);
  return token;
}

const routes = {
  'POST /api/register': async (req) => {
    if (limited('reg:' + ip(req), 10, 36e5)) throw new HttpErr(429, 'Demasiados registros desde esta conexión. Inténtalo más tarde.');
    const b = await readBody(req);
    const email = String(b.email || '').trim().toLowerCase(), name = String(b.name || '').trim(), pw = String(b.password || '');
    if (!EMAIL_RX.test(email)) throw new HttpErr(400, 'Escribe un correo electrónico válido.');
    if (!NAME_RX.test(name)) throw new HttpErr(400, 'El nombre debe tener entre 3 y 20 caracteres (letras, números, espacio, _ . -).');
    if (pw.length < 8 || pw.length > 200) throw new HttpErr(400, 'La contraseña debe tener al menos 8 caracteres.');
    let data = {}; if (b.data != null) { data = cleanData(b.data); if (!data) throw new HttpErr(400, 'Progreso no válido.'); }
    if (q.userByEmail.get(email)) throw new HttpErr(409, 'Ya existe una cuenta con ese correo. Inicia sesión.');
    const pwh = await hashPw(pw), now = Date.now();
    const out = tx(() => {
      if (q.userByEmail.get(email)) throw new HttpErr(409, 'Ya existe una cuenta con ese correo. Inicia sesión.');
      const r = q.insUser.run(email, name, cleanAvatar(b.avatar), cleanColor(b.color), pwh, JSON.stringify(data), now, now);
      const id = Number(r.lastInsertRowid);
      return { id, token: newSession(id, req) };
    });
    return [201, { token: out.token, user: publicUser(q.userById.get(out.id)) }];
  },
  'POST /api/login': async (req) => {
    const b = await readBody(req);
    const email = String(b.email || '').trim().toLowerCase(), pw = String(b.password || '');
    if (limited('li:ip:' + ip(req), 30, 15 * 60e3) || limited('li:em:' + email, 10, 15 * 60e3))
      throw new HttpErr(429, 'Demasiados intentos. Espera unos minutos e inténtalo de nuevo.');
    const u = q.userByEmail.get(email);
    const ok = u ? await checkPw(pw, u.pw) : (await checkPw(pw, await DUMMY), false);
    if (!ok) throw new HttpErr(401, 'Correo o contraseña incorrectos.');
    hits.delete('li:em:' + email);
    return [200, { token: newSession(u.id, req), user: publicUser(u) }];
  },
  'POST /api/logout': async (req) => { const { th } = authed(req); q.delSess.run(th); return [200, { ok: true }]; },
  'GET /api/me': async (req) => { const { user } = authed(req); return [200, { user: publicUser(user) }]; },
  'PUT /api/data': async (req) => {
    const { user } = authed(req);
    const b = await readBody(req); const data = cleanData(b.data);
    if (!data) throw new HttpErr(400, 'Progreso no válido.');
    const r = q.setData.run(JSON.stringify(data), Date.now(), user.id, Number(b.rev) | 0);
    if (!r.changes) throw new HttpErr(409, 'Hay una versión más reciente en la nube.', { user: publicUser(q.userById.get(user.id)) });
    return [200, { rev: q.userById.get(user.id).rev }];
  },
  'PUT /api/profile': async (req) => {
    const { user } = authed(req); const b = await readBody(req);
    q.setProfile.run(cleanAvatar(b.avatar ?? user.avatar), cleanColor(b.color ?? user.color), cleanBio(b.bio ?? user.bio), Date.now(), user.id);
    return [200, { ok: true }];
  },
  'POST /api/password': async (req) => {
    const { th, user } = authed(req); const b = await readBody(req);
    if (limited('pw:' + user.id, 10, 15 * 60e3)) throw new HttpErr(429, 'Demasiados intentos. Espera unos minutos.');
    const next = String(b.next || '');
    if (next.length < 8 || next.length > 200) throw new HttpErr(400, 'La nueva contraseña debe tener al menos 8 caracteres.');
    if (!(await checkPw(String(b.current || ''), user.pw))) throw new HttpErr(403, 'La contraseña actual no es correcta.');
    q.setPw.run(await hashPw(next), Date.now(), user.id);
    q.delOthers.run(user.id, th); // cierra la sesión en los demás dispositivos
    return [200, { ok: true }];
  },
  'DELETE /api/account': async (req) => {
    const { user } = authed(req); const b = await readBody(req);
    if (limited('del:' + user.id, 10, 15 * 60e3)) throw new HttpErr(429, 'Demasiados intentos. Espera unos minutos.');
    if (!(await checkPw(String(b.password || ''), user.pw))) throw new HttpErr(403, 'Contraseña incorrecta.');
    q.delUser.run(user.id);
    return [200, { ok: true }];
  },
};

/* ---------- estáticos (la web de Gotta) ---------- */
const files = new Map();
function loadStatic() {
  files.clear();
  const walk = d => { for (const f of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, f.name); if (f.isDirectory()) { walk(p); continue; }
    const rel = '/' + path.relative(PUBLIC_DIR, p).split(path.sep).join('/');
    const buf = fs.readFileSync(p); const ext = path.extname(f.name).toLowerCase();
    const type = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.webp': 'image/webp', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.woff2': 'font/woff2' }[ext] || 'application/octet-stream';
    const comp = /^(text|application\/json|image\/svg)/.test(type) ? zlib.gzipSync(buf, { level: 9 }) : null;
    files.set(rel, { buf, gz: comp, type, etag: '"' + sha(buf).slice(0, 20) + '"' });
  } };
  if (fs.existsSync(PUBLIC_DIR)) walk(PUBLIC_DIR);
}
loadStatic();
function serveStatic(req, res) {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (p === '/') p = '/index.html';
  const f = files.get(p) || (!path.extname(p) ? files.get('/index.html') : null);
  if (!f) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('No encontrado'); }
  const h = { 'Content-Type': f.type, ETag: f.etag, 'Cache-Control': p === '/index.html' ? 'no-cache' : 'public, max-age=86400', Vary: 'Accept-Encoding' };
  if (req.headers['if-none-match'] === f.etag) { res.writeHead(304, h); return res.end(); }
  const useGz = f.gz && /\bgzip\b/.test(req.headers['accept-encoding'] || '');
  if (useGz) h['Content-Encoding'] = 'gzip';
  const body = useGz ? f.gz : f.buf; h['Content-Length'] = body.length;
  res.writeHead(200, h); res.end(req.method === 'HEAD' ? undefined : body);
}

const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  if (TRUST_PROXY ? req.headers['x-forwarded-proto'] === 'https' : false) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  try {
    const url = new URL(req.url, 'http://x');
    if (url.pathname === '/healthz') return send(res, 200, { ok: true });
    if (url.pathname.startsWith('/api/')) {
      const h = routes[req.method + ' ' + url.pathname];
      if (!h) throw new HttpErr(404, 'No encontrado.');
      // Solo mismo origen: bloquea peticiones de otras webs
      const origin = req.headers.origin;
      if (origin && new URL(origin).host !== req.headers.host) throw new HttpErr(403, 'Origen no permitido.');
      const [status, obj] = await h(req);
      return send(res, status, obj);
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpErr(405, 'Método no permitido.');
    serveStatic(req, res);
  } catch (e) {
    if (e instanceof HttpErr) return send(res, e.status, { error: e.message, ...(e.extra || {}) });
    console.error(e);
    if (!res.headersSent) send(res, 500, { error: 'Error interno del servidor.' });
  }
});
server.requestTimeout = 30000;
server.listen(PORT, () => console.log(`Gotta escuchando en http://localhost:${PORT} · datos en ${DATA_DIR}`));
for (const s of ['SIGINT', 'SIGTERM']) process.on(s, () => { server.close(); try { db.close(); } catch {} process.exit(0); });

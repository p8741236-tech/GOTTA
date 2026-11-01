// Cliente mínimo de PostgreSQL sin dependencias: TLS, autenticación SCRAM-SHA-256 / md5 / texto plano,
// protocolo extendido (consultas con parámetros) y reconexión automática. Suficiente para Neon, Render, Supabase...
import net from 'node:net';
import tls from 'node:tls';
import crypto from 'node:crypto';

const i32 = n => { const b = Buffer.alloc(4); b.writeInt32BE(n); return b; };
const i16 = n => { const b = Buffer.alloc(2); b.writeInt16BE(n); return b; };
const cstr = s => Buffer.concat([Buffer.from(String(s), 'utf8'), Buffer.from([0])]);
const msg = (type, ...parts) => { const body = Buffer.concat(parts); return Buffer.concat([Buffer.from(type), i32(body.length + 4), body]); };
const hmac = (k, d) => crypto.createHmac('sha256', k).update(d).digest();

export function parseUrl(url) {
  const u = new URL(url);
  const host = u.hostname, local = ['localhost', '127.0.0.1', '::1'].includes(host);
  let mode = u.searchParams.get('sslmode') || (local ? 'disable' : 'require');
  if (u.searchParams.get('ssl') === 'true') mode = 'require';
  return { host, port: +u.port || 5432, user: decodeURIComponent(u.username), password: decodeURIComponent(u.password),
    database: decodeURIComponent(u.pathname.slice(1)) || decodeURIComponent(u.username), sslmode: mode };
}

class Conn {
  constructor(cfg) { this.cfg = cfg; this.buf = Buffer.alloc(0); this.waiter = null; this.dead = false; this.q = []; }
  async open() {
    const { host, port, sslmode } = this.cfg;
    let sock = await new Promise((res, rej) => { const s = net.connect({ host, port }); s.setNoDelay(true); s.once('connect', () => res(s)); s.once('error', rej); s.setTimeout(15000, () => { s.destroy(new Error('Tiempo de espera agotado al conectar con la base de datos')); }); });
    sock.setTimeout(0);
    if (sslmode !== 'disable') {
      sock.write(Buffer.concat([i32(8), i32(80877103)]));
      const ans = await new Promise((res, rej) => { sock.once('data', res); sock.once('error', rej); });
      if (ans[0] !== 0x53) throw new Error('El servidor de base de datos no admite TLS');
      sock = await new Promise((res, rej) => { const t = tls.connect({ socket: sock, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: sslmode !== 'no-verify' }, () => res(t)); t.once('error', rej); });
    }
    this.sock = sock;
    sock.on('data', d => { this.buf = Buffer.concat([this.buf, d]); this._wake(); });
    const fin = e => { this.dead = true; this.err = e || this.err || new Error('Conexión con la base de datos cerrada'); this._wake(); };
    sock.on('error', fin); sock.on('close', () => fin()); sock.on('end', () => fin());
    const body = Buffer.concat([i32(196608), cstr('user'), cstr(this.cfg.user), cstr('database'), cstr(this.cfg.database), cstr('client_encoding'), cstr('UTF8'), cstr('application_name'), cstr('gotta'), Buffer.from([0])]);
    sock.write(Buffer.concat([i32(body.length + 4), body]));
    await this._auth();
  }
  _wake() { const w = this.waiter; if (w) { this.waiter = null; w(); } }
  async _next() {
    for (;;) {
      if (this.buf.length >= 5) {
        const len = this.buf.readInt32BE(1);
        if (this.buf.length >= len + 1) { const m = { t: String.fromCharCode(this.buf[0]), b: this.buf.subarray(5, len + 1) }; this.buf = this.buf.subarray(len + 1); return m; }
      }
      if (this.dead) throw this.err || new Error('Conexión con la base de datos cerrada');
      await new Promise((r, rej) => { this.waiter = r; const t = setTimeout(() => { this.waiter = null; this.dead = true; this.sock.destroy(); rej(new Error('La base de datos no responde')); }, 60000); const o = this.waiter; this.waiter = () => { clearTimeout(t); o(); }; });
    }
  }
  static err(b) { const f = {}; let i = 0; while (b[i]) { const k = String.fromCharCode(b[i++]); let e = b.indexOf(0, i); f[k] = b.toString('utf8', i, e); i = e + 1; } const er = new Error(f.M || 'Error de base de datos'); er.code = f.C; er.detail = f.D; return er; }
  async _auth() {
    const { user, password } = this.cfg; let nonce, clientFirstBare, serverFirst, saltedPw, authMsg;
    for (;;) {
      const m = await this._next();
      if (m.t === 'E') throw Conn.err(m.b);
      if (m.t === 'R') {
        const code = m.b.readInt32BE(0);
        if (code === 0) continue;
        if (code === 3) this.sock.write(msg('p', cstr(password)));
        else if (code === 5) { const md5 = d => crypto.createHash('md5').update(d).digest('hex'); this.sock.write(msg('p', cstr('md5' + md5(Buffer.concat([Buffer.from(md5(password + user)), m.b.subarray(4, 8)]))))); }
        else if (code === 10) {
          nonce = crypto.randomBytes(18).toString('base64'); clientFirstBare = `n=*,r=${nonce}`;
          const first = Buffer.from('n,,' + clientFirstBare);
          this.sock.write(msg('p', cstr('SCRAM-SHA-256'), i32(first.length), first));
        } else if (code === 11) {
          serverFirst = m.b.subarray(4).toString(); const p = Object.fromEntries(serverFirst.split(',').map(x => [x[0], x.slice(2)]));
          if (!p.r.startsWith(nonce)) throw new Error('Autenticación SCRAM no válida');
          saltedPw = crypto.pbkdf2Sync(password.normalize('NFKC'), Buffer.from(p.s, 'base64'), +p.i, 32, 'sha256');
          const without = `c=biws,r=${p.r}`; authMsg = `${clientFirstBare},${serverFirst},${without}`;
          const ck = hmac(saltedPw, 'Client Key'), sk = crypto.createHash('sha256').update(ck).digest(), sig = hmac(sk, authMsg);
          const proof = Buffer.from(ck.map((v, i) => v ^ sig[i])).toString('base64');
          this.sock.write(msg('p', Buffer.from(`${without},p=${proof}`)));
        } else if (code === 12) {
          const v = m.b.subarray(4).toString().replace(/^v=/, ''); const want = hmac(hmac(saltedPw, 'Server Key'), authMsg).toString('base64');
          if (v !== want) throw new Error('La firma SCRAM del servidor no coincide');
        } else throw new Error('Método de autenticación no soportado: ' + code);
      } else if (m.t === 'Z') return;
    }
  }
  // Ejecuta una consulta con parámetros (texto). Devuelve { rows, count }.
  async query(sql, params = []) {
    const parts = [msg('P', cstr(''), cstr(sql), i16(0))];
    const vals = params.map(p => p == null ? i32(-1) : (b => Buffer.concat([i32(b.length), b]))(Buffer.from(String(p), 'utf8')));
    parts.push(msg('B', cstr(''), cstr(''), i16(0), i16(params.length), ...vals, i16(0)), msg('D', Buffer.from('P'), cstr('')), msg('E', cstr(''), i32(0)), msg('S'));
    this.sock.write(Buffer.concat(parts));
    return this._collect();
  }
  async simple(sql) { this.sock.write(msg('Q', cstr(sql))); return this._collect(); }
  async _collect() {
    let cols = [], rows = [], count = 0, error = null;
    for (;;) {
      const m = await this._next();
      if (m.t === 'E') error = Conn.err(m.b);
      else if (m.t === 'T') { const n = m.b.readInt16BE(0); cols = []; let i = 2; for (let k = 0; k < n; k++) { const e = m.b.indexOf(0, i); const name = m.b.toString('utf8', i, e); i = e + 1; const oid = m.b.readInt32BE(i + 6); cols.push({ name, oid }); i += 18; } }
      else if (m.t === 'D') {
        const n = m.b.readInt16BE(0); let i = 2; const r = {};
        for (let k = 0; k < n; k++) { const len = m.b.readInt32BE(i); i += 4; let v = null; if (len >= 0) { v = m.b.toString('utf8', i, i + len); i += len; const o = cols[k].oid; if (o === 20 || o === 21 || o === 23) v = Number(v); } r[cols[k].name] = v; }
        rows.push(r);
      } else if (m.t === 'C') { const tag = m.b.toString('utf8', 0, m.b.length - 1).split(' '); count = Number(tag[tag.length - 1]) || 0; }
      else if (m.t === 'Z') { if (error) throw error; return { rows, count }; }
    }
  }
  close() { try { this.sock.destroy(); } catch {} this.dead = true; }
}

export class Pg {
  constructor(url) { this.cfg = parseUrl(url); this.conn = null; this.chain = Promise.resolve(); }
  async _conn() {
    if (this.conn && !this.conn.dead) return this.conn;
    const c = new Conn(this.cfg); await c.open(); this.conn = c; return c;
  }
  // Las consultas se ejecutan de una en una. Si la conexión se cayó (p. ej. Neon suspende la base de datos), reconecta y reintenta una vez.
  run(fn) {
    const job = this.chain.then(async () => {
      for (let attempt = 0; ; attempt++) {
        let c;
        try { c = await this._conn(); return await fn(c); }
        catch (e) { if (e.code || attempt >= 2) throw e; if (c) c.close(); this.conn = null; await new Promise(r => setTimeout(r, 300 * (attempt + 1))); }
      }
    });
    this.chain = job.catch(() => {});
    return job;
  }
  query(sql, params) { return this.run(c => c.query(sql, params)); }
  exec(sql) { return this.run(c => c.simple(sql)); }
  close() { if (this.conn) this.conn.close(); }
}

import { spawn } from 'node:child_process';
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';
import assert from 'node:assert/strict';
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gotta-'));
const PORT = 3111, B = `http://localhost:${PORT}`;
const start = () => spawn('node', ['server.js'], { env: { ...process.env, PORT, DATA_DIR: dir }, stdio: 'ignore' });
let srv = start(); await new Promise(r => setTimeout(r, 1200));
const call = async (m, p, body, tok) => { const r = await fetch(B + p, { method: m, headers: { 'Content-Type': 'application/json', ...(tok ? { Authorization: 'Bearer ' + tok } : {}) }, body: body && JSON.stringify(body) }); return [r.status, await r.json().catch(() => null)]; };
const data = { 'arc-p': '{"snake":3}', 'gotta-ach': '{"u":{"g:first":1}}' };
let [s, r] = await call('POST', '/api/register', { email: 'Ana@Test.com', name: 'Ana', password: 'secreto123', avatar: '🦊', color: '#22d3ee', data });
assert.equal(s, 201); const tokA = r.token; assert.equal(r.user.email, 'ana@test.com');
[s] = await call('POST', '/api/register', { email: 'ana@test.com', name: 'Otra', password: 'secreto123' }); assert.equal(s, 409);
[s] = await call('POST', '/api/register', { email: 'x@y.com', name: 'Xx', password: 'corta' }); assert.equal(s, 400);
[s] = await call('POST', '/api/login', { email: 'ana@test.com', password: 'mala' }); assert.equal(s, 401);
// "otro dispositivo": reinicia el servidor y entra con correo+contraseña
srv.kill(); await new Promise(r => setTimeout(r, 500)); srv = start(); await new Promise(r => setTimeout(r, 1200));
[s, r] = await call('POST', '/api/login', { email: 'ANA@test.com', password: 'secreto123' });
assert.equal(s, 200); assert.deepEqual(r.user.data, data); const tokB = r.token; assert.notEqual(tokA, tokB);
[s, r] = await call('GET', '/api/me', null, tokA); assert.equal(s, 200, 'la sesión antigua sigue valiendo tras reiniciar');
// sincronización con control de versión
let rev = r.user.rev;
[s, r] = await call('PUT', '/api/data', { data: { ...data, 'arc-p': '{"snake":9}' }, rev }, tokB); assert.equal(s, 200); assert.equal(r.rev, rev + 1);
[s, r] = await call('PUT', '/api/data', { data, rev }, tokA); assert.equal(s, 409); assert.equal(r.user.data['arc-p'], '{"snake":9}');
[s] = await call('PUT', '/api/data', { data: { 'arc-p': 'no-json' }, rev: 2 }, tokB); assert.equal(s, 400);
[s] = await call('GET', '/api/me', null, 'x'.repeat(30)); assert.equal(s, 401);
// perfil, contraseña, logout, borrado
[s] = await call('PUT', '/api/profile', { avatar: '🐼', color: '#ff6a00', bio: 'hola' }, tokB); assert.equal(s, 200);
[s] = await call('POST', '/api/password', { current: 'mala', next: 'nuevaclave1' }, tokB); assert.equal(s, 403);
[s] = await call('POST', '/api/password', { current: 'secreto123', next: 'nuevaclave1' }, tokB); assert.equal(s, 200);
[s] = await call('GET', '/api/me', null, tokA); assert.equal(s, 401, 'cambiar contraseña cierra las otras sesiones');
[s] = await call('POST', '/api/login', { email: 'ana@test.com', password: 'secreto123' }); assert.equal(s, 401);
[s, r] = await call('POST', '/api/login', { email: 'ana@test.com', password: 'nuevaclave1' }); assert.equal(s, 200); assert.equal(r.user.bio, 'hola');
[s] = await call('POST', '/api/logout', null, r.token); assert.equal(s, 200);
[s] = await call('GET', '/api/me', null, r.token); assert.equal(s, 401);
[s] = await call('DELETE', '/api/account', { password: 'x' }, tokB); assert.equal(s, 403);
[s] = await call('DELETE', '/api/account', { password: 'nuevaclave1' }, tokB); assert.equal(s, 200);
[s] = await call('POST', '/api/login', { email: 'ana@test.com', password: 'nuevaclave1' }); assert.equal(s, 401);
// límite de intentos
let last; for (let i = 0; i < 12; i++) [last] = await call('POST', '/api/login', { email: 'bruto@x.com', password: 'p' + i }); assert.equal(last, 429);
const h = await fetch(B + '/'); assert.equal(h.status, 200); assert.match(await h.text(), /Gotta/);
srv.kill(); console.log('API OK');

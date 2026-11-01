import { spawn } from 'node:child_process';
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const { chromium } = createRequire('/opt/npm-tools/node_modules/')('playwright');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gotta-')), PORT = 3112, B = `http://localhost:${PORT}`;
const srv = spawn('node', ['server.js'], { env: { ...process.env, PORT, DATA_DIR: dir }, stdio: 'ignore' });
await new Promise(r => setTimeout(r, 1200));
const br = await chromium.launch();
const errs = [];
const mk = async () => { const c = await br.newContext({ viewport: { width: 1100, height: 800 } }); const p = await c.newPage(); p.on('pageerror', e => errs.push(e.message)); await p.goto(B, { waitUntil: 'domcontentloaded' }); await p.waitForSelector('#gx-btn', { state: 'attached', timeout: 20000 }); await p.waitForTimeout(1500); return p; };
// Dispositivo A
const A = await mk();
await A.evaluate(() => { localStorage.setItem('arc-p', JSON.stringify({ snake: 7, tres: 2 })); });
await A.evaluate(() => document.getElementById('gx-btn').click());
await A.waitForSelector('#gx-f');
await A.click('[data-at="reg"]');
await A.fill('#gx-u', 'Luis@Correo.es'); await A.fill('#gx-n', 'Luis'); await A.fill('#gx-p', 'miclave2026'); await A.fill('#gx-p2', 'miclave2026');
await A.click('#gx-go');
await A.waitForSelector('.gx-hd h2:has-text("Luis")', { timeout: 10000 });
console.log('registrado:', await A.textContent('.gx-hd__t p'));
await A.waitForTimeout(6000); // espera al envío automático
// Dispositivo B (contexto nuevo = otro navegador, sin nada guardado)
const Bp = await mk();
assert.equal(await Bp.evaluate(() => localStorage.getItem('arc-p')), null);
await Bp.evaluate(() => document.getElementById('gx-btn').click());
await Bp.waitForSelector('#gx-f');
await Bp.fill('#gx-u', 'luis@correo.es'); await Bp.fill('#gx-p', 'incorrecta1'); await Bp.click('#gx-go');
await Bp.waitForFunction(() => /incorrectos/.test(document.getElementById('gx-m').textContent), null, { timeout: 8000 });
console.log('mala contraseña ->', await Bp.textContent('#gx-m'));
await Bp.fill('#gx-p', 'miclave2026'); await Bp.click('#gx-go');
await Bp.waitForSelector('.gx-hd h2:has-text("Luis")', { timeout: 10000 });
const p = await Bp.evaluate(() => localStorage.getItem('arc-p'));
console.log('progreso en B:', p);
assert.deepEqual(JSON.parse(p), { snake: 7, tres: 2 });
// recarga en B: la sesión persiste
await Bp.reload({ waitUntil: 'domcontentloaded' }); await Bp.waitForSelector('#gx-btn', { state: 'attached' }); await Bp.waitForTimeout(1500);
assert.match(await Bp.textContent('#gx-btn .gx-nm'), /Luis/);
// B juega más y A lo recibe al volver
await Bp.evaluate(() => { localStorage.setItem('arc-p', JSON.stringify({ snake: 12, tres: 2 })); GX.flush(); });
await Bp.waitForTimeout(6000);
await A.reload({ waitUntil: 'domcontentloaded' }); await A.waitForSelector('#gx-btn', { state: 'attached' }); await A.waitForTimeout(2500);
console.log('progreso en A tras sincronizar:', await A.evaluate(() => localStorage.getItem('arc-p')));
assert.equal(JSON.parse(await A.evaluate(() => localStorage.getItem('arc-p'))).snake, 12);
// cerrar sesión limpia el dispositivo
await A.evaluate(() => document.getElementById('gx-btn').click()); await A.click('[data-tab="cta"]'); await A.click('#gx-out');
await A.waitForTimeout(800); assert.match(await A.textContent('#gx-btn .gx-nm'), /Entrar/);
console.log('errores de página:', errs.filter(e => !/three|WebGL/i.test(e)));
await br.close(); srv.kill(); console.log('E2E OK');

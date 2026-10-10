// End-to-end test of the in-browser demo (scripts/build-demo.sh output) in a real
// headless Chrome, driven over the DevTools protocol. Needs Node 22 (built-in
// WebSocket and fetch) and Chrome; set CHROME to the browser path if it is not
// on PATH as google-chrome.
//
//   node scripts/demo-test.mjs DEMO_DIR        (serves the directory itself, under /logscrub/)
//   node scripts/demo-test.mjs https://host/p/ (tests a deployed site instead)
//
// Checks: the page works from a sub-path (like GitHub Pages); text is scrubbed in
// the browser; every request stays on the page's own origin and none is a POST;
// the CSP blocks loads from other origins; pseudonym mode and typed input work.
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, extname, normalize } from 'node:path';

const dir = process.argv[2];
if (!dir) { console.error('usage: node scripts/demo-test.mjs DEMO_DIR_OR_URL'); process.exit(2); }
const remote = /^https?:\/\//.test(dir);

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.wasm': 'application/wasm' };
const PREFIX = remote ? new URL(dir).pathname.replace(/\/?$/, '/') : '/logscrub/';
const failures = [];
const check = (ok, what, detail = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}${detail ? ' ' + detail : ''}`); if (!ok) failures.push(what); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- static server under /logscrub/ (as GitHub Pages serves a project site) ----
const hits = [];
const server = createServer(async (req, res) => {
  hits.push(`${req.method} ${req.url}`);
  const url = new URL(req.url, 'http://x');
  if (!url.pathname.startsWith(PREFIX)) { res.writeHead(404).end('not found'); return; }
  let rel = url.pathname.slice(PREFIX.length);
  if (rel === '' || rel.endsWith('/')) rel += 'index.html';
  rel = normalize(rel);
  if (rel.startsWith('..')) { res.writeHead(400).end(); return; }
  try {
    const body = await readFile(join(dir, rel));
    res.writeHead(200, { 'Content-Type': TYPES[extname(rel)] || 'application/octet-stream' }).end(body);
  } catch { res.writeHead(404).end('not found'); }
});
if (!remote) await new Promise((r) => server.listen(0, '127.0.0.1', r));
const origin = remote ? new URL(dir).origin : `http://127.0.0.1:${server.address().port}`;
const pageURL = `${origin}${PREFIX}`;

// ---- a second server that must never be contacted ----
const strangerHits = [];
const stranger = createServer((req, res) => { strangerHits.push(req.url); res.writeHead(200, { 'Access-Control-Allow-Origin': '*' }).end('x'); });
await new Promise((r) => stranger.listen(0, '127.0.0.1', r));
const strangerOrigin = `http://127.0.0.1:${stranger.address().port}`;

// ---- headless Chrome ----
const profile = await mkdtemp(join(tmpdir(), 'logscrub-demo-'));
const port = 9400 + Math.floor(Math.random() * 400);
const chrome = spawn(process.env.CHROME || 'google-chrome', [
  '--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`,
  '--no-first-run', '--no-default-browser-check', '--disable-extensions', '--no-sandbox', 'about:blank',
], { stdio: 'ignore' });
let up = false;
for (let i = 0; i < 100 && !up; i++) { try { await fetch(`http://127.0.0.1:${port}/json/version`); up = true; } catch { await sleep(100); } }
if (!up) { console.error('Chrome did not start'); process.exit(2); }

const target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: 'PUT' })).json();
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0; const pending = new Map(); const requests = [];
ws.onmessage = (m) => {
  const d = JSON.parse(m.data);
  if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); }
  else if (d.method === 'Network.requestWillBeSent') requests.push({ url: d.params.request.url, method: d.params.request.method, body: d.params.request.postData || '' });
};
const send = (method, params = {}) => new Promise((res, rej) => { const i = ++id; pending.set(i, (d) => d.error ? rej(new Error(`${method}: ${d.error.message}`)) : res(d.result)); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (expr) => { const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true }); if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails).slice(0, 400)); return r.result.value; };
await send('Network.enable');
await send('Page.enable');

async function waitFor(expr, what, ms = 20000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { try { if (await ev(expr)) return true; } catch { /* page still loading */ } await sleep(150); }
  let dump = '';
  try { dump = await ev(`document.title + ' | ' + location.href + ' | ' + document.body.innerText.slice(0, 200)`); } catch { /* ignore */ }
  check(false, `timed out waiting for ${what}`, `[page: ${dump}] [server saw: ${hits.join(', ')}]`);
  return false;
}

try {
  await send('Page.addScriptToEvaluateOnNewDocument', { source: `window.__violations = []; document.addEventListener('securitypolicyviolation', e => window.__violations.push(e.violatedDirective + ' ' + e.blockedURI));` });
  await send('Page.navigate', { url: pageURL });

  // 1. loads from the sub-path and scrubs the preloaded sample in the browser
  const loaded = await waitFor(`document.getElementById('status').textContent.includes('would be masked')`, 'the sample to be scrubbed');
  check(loaded, 'the page loads from a sub-path and scrubs the sample');
  const first = JSON.parse(await ev(`JSON.stringify({
    status: document.getElementById('status').textContent,
    marks: document.querySelectorAll('#preview mark').length,
    cleaned: document.getElementById('clean').textContent,
    detectors: document.querySelectorAll('#detectors input').length,
    title: document.title, privacy: document.querySelector('.privacy').textContent, banner: !!document.querySelector('.demo-banner')
  })`));
  check(first.marks >= 8, 'the sample is highlighted', `(${first.marks} matches: ${first.status})`);
  check(first.cleaned.includes('[REDACTED:') && !first.cleaned.includes('AKIAIOSFODNN7EXAMPLE') && !first.cleaned.includes('s3cretpass'), 'the cleaned text has no secrets left');
  check(first.detectors >= 30, 'all detectors are offered', `(${first.detectors})`);
  check(first.banner && first.privacy.includes('browser') && !first.privacy.includes('local logscrub process'), 'the demo wording is honest (runs in the browser)');

  // 2. pseudonym mode, custom text, detector toggle
  await ev(`document.querySelector('input[name=mode][value=pseudonym]').click(); new Promise(r => setTimeout(r, 900))`);
  const pseud = await ev(`document.getElementById('clean').textContent`);
  check(/\[email:[a-z2-7]{8}\]/.test(pseud) && pseud.includes('[REDACTED:aws-access-key]'), 'pseudonym mode gives stable tags for emails and fixed markers for secrets');
  await ev(`document.querySelector('input[name=mode][value=marker]').click(); (async () => { const t = document.getElementById('input'); t.value = 'ping carol@example.org token=abc123secret /home/carol/x'; t.dispatchEvent(new Event('input')); await new Promise(r => setTimeout(r, 1000)); })()`);
  const typed = await ev(`document.getElementById('clean').textContent`);
  check(typed === 'ping [REDACTED:email] token=[REDACTED:kv-secret] /home/[REDACTED:home-path]/x', 'typed text is scrubbed', JSON.stringify(typed));
  await ev(`(async () => { const cb = [...document.querySelectorAll('#detectors input')].find(c => c.value === 'email'); cb.click(); await new Promise(r => setTimeout(r, 900)); })()`);
  check((await ev(`document.getElementById('clean').textContent`)).startsWith('ping carol@example.org'), 'turning a detector off takes effect');
  await ev(`document.getElementById('sample').click(); new Promise(r => setTimeout(r, 900))`);
  check((await ev(`document.querySelectorAll('#preview mark').length`)) > 0, '"Load sample" works');

  // 3. nothing leaves the page
  const external = requests.filter((r) => !r.url.startsWith(origin + PREFIX) && !r.url.startsWith('data:') && !r.url.startsWith('about:'));
  check(external.length === 0, 'every request stays on the page\'s own origin', external.length ? JSON.stringify(external.map((r) => r.url)) : `(${requests.length} requests)`);
  check(!requests.some((r) => r.method !== 'GET'), 'no request is a POST (or anything but a GET)');
  check(!requests.some((r) => r.body.includes('carol') || r.body.includes('s3cretpass')), 'no request body contains the text');
  const urls = [...new Set(requests.map((r) => r.url.replace(origin, '')))];
  const own = new RegExp('^' + PREFIX.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(|app\\.js|demo\\.js|style\\.css|wasm_exec\\.js|logscrub\\.wasm)$');
  check(urls.every((u) => own.test(u)), 'only the demo\'s own files were fetched', JSON.stringify(urls));
  if (!remote) check(hits.every((h) => h.startsWith('GET ')), 'the static server saw only GETs');

  // 4. the CSP really blocks other origins (decided by violation events and by the stranger server never being hit)
  const probes = await ev(`(async () => {
    const out = {};
    out.fetch = await fetch(${JSON.stringify(strangerOrigin)} + '/f').then(() => 'SUCCEEDED').catch(() => 'blocked');
    out.img = await new Promise(r => { const i = new Image(); i.onload = () => r('LOADED'); i.onerror = () => r('blocked'); i.src = ${JSON.stringify(strangerOrigin)} + '/i.png'; });
    out.script = await new Promise(r => { const s = document.createElement('script'); s.onload = () => r('LOADED'); s.onerror = () => r('blocked'); s.src = ${JSON.stringify(strangerOrigin)} + '/s.js'; document.head.append(s); });
    await new Promise(r => setTimeout(r, 500));
    out.violations = window.__violations;
    return JSON.stringify(out);
  })()`);
  const p = JSON.parse(probes);
  check(p.fetch === 'blocked' && p.img === 'blocked' && p.script === 'blocked', 'the CSP blocks fetch, image and script loads from another origin');
  check(strangerHits.length === 0, 'the other origin never received a request', strangerHits.length ? JSON.stringify(strangerHits) : '');
  const normalViolations = p.violations.filter((v) => !v.includes(strangerOrigin));
  check(normalViolations.length === 0, 'normal use causes no CSP violations', normalViolations.length ? JSON.stringify(normalViolations) : '');
} catch (err) {
  check(false, 'the test ran without an exception', String(err));
} finally {
  ws.close();
  chrome.kill();
  if (!remote) server.close();
  stranger.close();
  await sleep(300);
  await rm(profile, { recursive: true, force: true }).catch(() => {});
}
console.log(failures.length ? `\n${failures.length} check(s) failed` : '\nall checks passed');
process.exit(failures.length ? 1 : 0);

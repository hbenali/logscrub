// logscrub web UI. Log text only ever goes to this page's own server
// (POST /api/scrub). Everything derived from the log is inserted with
// textContent / createTextNode, never as HTML.
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const input = $('input'), statusEl = $('status'), errorEl = $('error');
  const summary = $('summary'), preview = $('preview'), clean = $('clean');
  const copyBtn = $('copy'), downloadBtn = $('download');
  const MAX_MARKS = 20000;
  const HUES = 8;

  // The access token (only needed when the server requires one) lives in
  // memory. It arrives in the URL fragment, which browsers never send to a
  // server, and is removed from the address bar straight away.
  let token = '';
  const hashToken = new URLSearchParams(location.hash.slice(1)).get('token');
  if (hashToken) {
    token = hashToken;
    history.replaceState(null, '', location.pathname + location.search);
  }

  let detectors = [];
  let maxBytes = 10 * 1024 * 1024;
  let timer = null, seq = 0, controller = null;
  let lastOutput = '';

  const hueOf = (id) => {
    const i = detectors.findIndex((d) => d.id === id);
    return 'h' + (Math.max(i, 0) % HUES);
  };

  function setError(msg) {
    errorEl.hidden = !msg;
    errorEl.textContent = msg || '';
  }

  function selectedIds() {
    return [...document.querySelectorAll('#detectors input:checked')].map((el) => el.value);
  }

  function mode() {
    return document.querySelector('input[name="mode"]:checked').value;
  }

  function authHeaders(extra) {
    const h = Object.assign({}, extra);
    if (token) h.Authorization = 'Bearer ' + token;
    return h;
  }

  const tokenForm = $('tokenform'), tokenInput = $('token'), tokenError = $('token-error');

  function askForToken(wrong) {
    tokenForm.hidden = false;
    tokenError.hidden = !wrong;
    tokenError.textContent = wrong ? 'That token was not accepted.' : '';
    tokenInput.value = '';
    tokenInput.focus();
  }

  class NeedToken extends Error {}

  async function loadDetectors() {
    const res = await fetch('/api/detectors', { headers: authHeaders() });
    if (res.status === 401) throw new NeedToken();
    if (!res.ok) throw new Error('could not load the detector list');
    const body = await res.json();
    detectors = body.detectors;
    maxBytes = body.maxBodyBytes;
    const box = $('detectors');
    box.textContent = '';
    detectors.forEach((d) => {
      const label = document.createElement('label');
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.value = d.id;
      cb.checked = d.default;
      cb.addEventListener('change', schedule);
      const sw = document.createElement('span');
      sw.className = 'swatch ' + hueOf(d.id);
      const text = document.createElement('span');
      text.className = 'text';
      const name = document.createElement('span');
      name.textContent = d.id + (d.optional ? ' (opt-in)' : '');
      const desc = document.createElement('small');
      desc.textContent = d.desc;
      text.append(name, desc);
      label.append(cb, sw, text);
      box.append(label);
    });
  }

  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(run, 250);
  }

  async function run() {
    const text = input.value;
    const my = ++seq;
    if (controller) controller.abort();
    if (text === '') {
      render(text, { output: '', spans: [], counts: {}, warnings: [] });
      statusEl.textContent = 'Nothing to scrub yet.';
      return;
    }
    const bytes = new TextEncoder().encode(text).length;
    if (bytes > maxBytes) {
      setError('That text is ' + bytes.toLocaleString() + ' bytes; the limit is ' + maxBytes.toLocaleString() + '.');
      return;
    }
    controller = new AbortController();
    statusEl.textContent = 'Scanning…';
    try {
      const res = await fetch('/api/scrub', {
        method: 'POST',
        headers: authHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ text, detectors: selectedIds(), mode: mode() }),
        signal: controller.signal,
      });
      const body = await res.json();
      if (my !== seq) return; // a newer request superseded this one
      if (res.status === 401) {
        askForToken(true);
        return;
      }
      if (!res.ok) {
        setError(body.error || 'The request failed.');
        return;
      }
      setError('');
      render(text, body);
    } catch (err) {
      if (err.name === 'AbortError') return;
      setError('Could not reach the local logscrub server.');
    }
  }

  function render(text, body) {
    lastOutput = body.output;
    clean.textContent = body.output;
    copyBtn.disabled = downloadBtn.disabled = text === '';

    summary.textContent = '';
    let total = 0;
    Object.keys(body.counts).sort().forEach((id) => {
      total += body.counts[id];
      const li = document.createElement('li');
      li.className = hueOf(id);
      li.textContent = id + ': ' + body.counts[id];
      summary.append(li);
    });

    // Offsets are UTF-8 byte offsets; slice the encoded bytes and decode each
    // piece so non-ASCII text lines up.
    const bytes = new TextEncoder().encode(text);
    const dec = new TextDecoder();
    const frag = document.createDocumentFragment();
    let pos = 0;
    body.spans.slice(0, MAX_MARKS).forEach((s) => {
      if (s.start > pos) frag.append(dec.decode(bytes.subarray(pos, s.start)));
      const mark = document.createElement('mark');
      mark.className = hueOf(s.detector);
      mark.title = s.detector + ' → ' + s.replacement;
      mark.textContent = dec.decode(bytes.subarray(s.start, s.end));
      frag.append(mark);
      pos = s.end;
    });
    frag.append(dec.decode(bytes.subarray(pos)));
    preview.textContent = '';
    preview.append(frag);

    let msg = total === 0 ? 'Nothing would be masked.' : total + ' item' + (total === 1 ? '' : 's') + ' would be masked.';
    if (body.spansTruncated || body.spans.length > MAX_MARKS) msg += ' Highlighting shows the first ' + Math.min(body.spans.length, MAX_MARKS) + '.';
    if (body.warnings.length) msg += ' ' + body.warnings.join(' ');
    statusEl.textContent = msg;
  }

  function showTab(which) {
    const isPreview = which === 'preview';
    $('tab-preview').setAttribute('aria-selected', String(isPreview));
    $('tab-preview').tabIndex = isPreview ? 0 : -1;
    $('tab-clean').setAttribute('aria-selected', String(!isPreview));
    $('tab-clean').tabIndex = isPreview ? -1 : 0;
    preview.hidden = !isPreview;
    clean.hidden = isPreview;
  }

  async function readFile(file) {
    if (file.size > maxBytes) {
      setError('That file is ' + file.size.toLocaleString() + ' bytes; the limit is ' + maxBytes.toLocaleString() + '.');
      return;
    }
    input.value = await file.text(); // read in the browser; nothing is uploaded except to this server for scanning
    schedule();
  }

  input.addEventListener('input', schedule);
  input.addEventListener('dragover', (e) => { e.preventDefault(); input.classList.add('drag'); });
  input.addEventListener('dragleave', () => input.classList.remove('drag'));
  input.addEventListener('drop', (e) => {
    e.preventDefault();
    input.classList.remove('drag');
    const f = e.dataTransfer.files[0];
    if (f) readFile(f);
  });
  $('file').addEventListener('change', (e) => { if (e.target.files[0]) readFile(e.target.files[0]); e.target.value = ''; });
  $('clear').addEventListener('click', () => { input.value = ''; setError(''); run(); input.focus(); });
  document.querySelectorAll('input[name="mode"]').forEach((el) => el.addEventListener('change', schedule));
  $('tab-preview').addEventListener('click', () => showTab('preview'));
  $('tab-clean').addEventListener('click', () => showTab('clean'));

  copyBtn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(lastOutput);
      statusEl.textContent = 'Copied the cleaned text.';
    } catch {
      setError('Copying was blocked by the browser; use Download instead.');
    }
  });
  downloadBtn.addEventListener('click', () => {
    const url = URL.createObjectURL(new Blob([lastOutput], { type: 'text/plain' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = 'clean.log';
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });

  function start() {
    tokenForm.hidden = true;
    loadDetectors().then(run).catch((err) => {
      if (err instanceof NeedToken) askForToken(Boolean(token));
      else setError(err.message);
    });
  }

  tokenForm.addEventListener('submit', (e) => {
    e.preventDefault();
    token = tokenInput.value.trim();
    start();
  });

  // Tabs: arrow keys, Home and End move between them (ARIA tab pattern).
  const tabs = [$('tab-preview'), $('tab-clean')];
  tabs.forEach((tab, i) => tab.addEventListener('keydown', (e) => {
    let next = -1;
    if (e.key === 'ArrowRight') next = (i + 1) % tabs.length;
    else if (e.key === 'ArrowLeft') next = (i + tabs.length - 1) % tabs.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = tabs.length - 1;
    if (next < 0) return;
    e.preventDefault();
    showTab(next === 0 ? 'preview' : 'clean');
    tabs[next].focus();
  }));

  start();
})();

#!/usr/bin/env bash
# Builds the in-browser demo: the real web UI (internal/serve/web) with the
# engine compiled to WebAssembly instead of a server behind it. The result is a
# static site (GitHub Pages) where pasted text never leaves the browser.
#
# Usage: scripts/build-demo.sh OUTDIR [VERSION]
set -euo pipefail

out="${1:?usage: build-demo.sh OUTDIR [VERSION]}"
version="${2:-$(git describe --tags --always 2>/dev/null || echo dev)}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

rm -rf "$out"
mkdir -p "$out"
cp "$root"/internal/serve/web/{index.html,app.js,style.css} "$out/"

GOOS=js GOARCH=wasm go build -C "$root" -trimpath -ldflags "-s -w -X main.version=${version}" \
  -o "$out/logscrub.wasm" ./cmd/logscrub-wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" "$out/wasm_exec.js"

cat > "$out/demo.js" <<'JS'
// Backend for the in-browser demo: the engine compiled to WebAssembly. It
// replaces the HTTP calls the local server's UI makes; nothing here uses the network
// except loading logscrub.wasm from the page's own origin.
(() => {
  'use strict';
  window.logscrubDemo = true;

  const ready = (async () => {
    const go = new Go();
    let instance;
    try {
      ({ instance } = await WebAssembly.instantiateStreaming(fetch('logscrub.wasm'), go.importObject));
    } catch (err) {
      const bytes = await (await fetch('logscrub.wasm')).arrayBuffer(); // servers without the wasm MIME type
      ({ instance } = await WebAssembly.instantiate(bytes, go.importObject));
    }
    go.run(instance); // does not return: the Go side keeps answering calls
    for (let i = 0; i < 300 && !window.logscrub; i++) await new Promise((r) => setTimeout(r, 10));
    if (!window.logscrub) throw new Error('The WebAssembly module did not start.');
  })();

  window.logscrubBackend = {
    async detectors() {
      await ready;
      return JSON.parse(window.logscrub.detectors());
    },
    async scrub(request) {
      await ready;
      const r = JSON.parse(window.logscrub.scrub(JSON.stringify(request)));
      return { status: r.status, ok: r.status === 200, body: r.body };
    },
  };
})();
JS

cat >> "$out/style.css" <<'CSS'

.demo-banner { max-width: 1168px; margin: 10px auto 0; padding: 10px 14px; border: 1px solid var(--border); border-radius: 8px; background: var(--panel); color: var(--text); }
.demo-banner a { color: var(--accent); }
CSS

python3 - "$out/index.html" <<'PY'
import re, sys
path = sys.argv[1]
s = open(path, encoding='utf-8').read()

def replace(old, new, regex=False):
    global s
    found = re.search(old, s, re.S) if regex else (old in s)
    if not found:
        sys.exit(f'build-demo: expected markup not found: {old[:60]!r}')
    s = re.sub(old, new, s, count=1, flags=re.S) if regex else s.replace(old, new, 1)

csp = ("default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; "
       "img-src 'self' data:; base-uri 'none'; form-action 'none'")
replace('<meta charset="utf-8">', f'<meta charset="utf-8">\n<meta http-equiv="Content-Security-Policy" content="{csp}">')
replace('<title>logscrub</title>', '<title>logscrub demo</title>')
replace('href="/style.css"', 'href="style.css"')
replace('<script src="/app.js"></script>',
        '<script src="wasm_exec.js"></script>\n<script src="demo.js"></script>\n<script src="app.js"></script>')
replace(r'<p class="privacy">.*?</p>',
        '<p class="privacy">Runs entirely in your browser (WebAssembly). Nothing you type or paste is sent anywhere.</p>', regex=True)
replace('</header>', '''</header>
<div class="demo-banner" role="note">
  <strong>Demo.</strong> This is the real logscrub engine compiled to WebAssembly: open your browser's network tab and you will see no request carrying your text.
  The tool itself runs locally: <a href="https://github.com/hbenali/logscrub#install">install it</a> (<code>brew install hbenali/tap/logscrub</code>, packages, Docker) or read the
  <a href="https://github.com/hbenali/logscrub/wiki">docs</a>.
</div>''')
open(path, 'w', encoding='utf-8').write(s)
PY

# Nothing in the page may refer to another origin (links in the banner are navigations, not loads).
if grep -nE '(src|href)="https?://' "$out/index.html" | grep -v 'github.com/hbenali/logscrub'; then
  echo "build-demo: the page references another origin" >&2; exit 1
fi
echo "demo built in $out ($(du -sh "$out" | cut -f1); wasm $(du -h "$out/logscrub.wasm" | cut -f1))"

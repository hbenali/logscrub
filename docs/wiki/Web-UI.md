# Web UI

## The online demo

**https://logscrub.hbenali.ovh/** is the same page with the engine compiled to WebAssembly instead of a server behind it, hosted as a static site on GitHub Pages. Your text is processed by code running in your own browser and is not sent anywhere: the page's CSP only allows loading its own files, there is no server to receive text (so no POST is ever made), and you can confirm it in the browser's network tab. It starts with a made-up sample log; the "Load sample" button brings it back. Text is limited to 2 MiB because WebAssembly runs on the page's main thread. A hosted *server* demo would have meant pasting logs into someone else's machine, which is exactly what logscrub exists to avoid, so there isn't one.

The site is built from the same `internal/serve/web` files as the local UI by `scripts/build-demo.sh`, deployed by `.github/workflows/pages.yml` on every change to the engine or UI, and tested in a real headless Chrome before each deploy (`scripts/demo-test.mjs`): it checks that text is scrubbed in the browser, that no request leaves the page's origin or carries the text, and that the CSP blocks other origins.

## Running it locally

`logscrub serve` starts a local page for people who would rather paste than pipe.

```sh
logscrub serve                          # http://127.0.0.1:8080
logscrub serve --addr 127.0.0.1:9000 --config logscrub.toml --key-file key.txt
```

![The logscrub web UI with a pasted log and every match highlighted by detector](https://raw.githubusercontent.com/hbenali/logscrub/main/docs/screenshots/web-ui.png)

Paste a log or drop a file onto the text box. The page shows the text with every match highlighted (hover a highlight to see the detector and its replacement), a count per detector, and the cleaned text. Use the checkboxes to turn detectors on or off, choose fixed markers or stable tags for emails and IPs, and download or copy the cleaned text. `--config` and `--key-file` work as in the CLI (see [Configuration](Configuration)); the config's allow-list and custom rules apply, and its enable/disable lists set the initial checkboxes.

In pseudonym mode the cleaned text keeps the log debuggable: the same address always gets the same tag, while secrets keep fixed markers (dark theme shown; the page follows your system setting).

![The cleaned text in pseudonym mode, with tags such as [email:ggyjbrrk] and [ipv4:znrrpfi2]](https://raw.githubusercontent.com/hbenali/logscrub/main/docs/screenshots/web-ui-pseudonyms.png)

## What it does with your text

- The text goes from the page to the local `logscrub` process and back. It is processed in memory by the same engine as the CLI, never written to disk, and never logged (the server logs only its start-up line and errors, without request content).
- The page loads no scripts, fonts, images or styles from other sites and makes no other network requests. A strict Content-Security-Policy enforces this (`default-src 'none'`; only the page's own script and stylesheet; connections only back to the server), and log text is inserted with `textContent`, never as HTML, so a log line containing `<script>` is just text.
- The pseudonym key stays on the server (`--key-file`, `LOGSCRUB_KEY`, or random for the run); the browser never sees it.

## Staying safe

A server on your machine can be reached by every web page you visit, so it defends itself:

- **Loopback only by default.** Other addresses are refused unless you pass `--allow-remote`. A non-loopback bind **requires an access token**: pass `--token-file FILE` (or `LOGSCRUB_TOKEN`), or let logscrub generate a random 128-bit one and print `http://HOST:PORT/#token=...`. The token is in the URL *fragment*, which browsers never send to a server or put in a Referer header; the page keeps it in memory, removes it from the address bar, and sends it as `Authorization: Bearer ...`. The API compares it in constant time; the page itself (which holds nothing sensitive) loads without it and asks for the token if needed. A token is optional on loopback (`--token-file`).
- **Plain HTTP.** The token and your text are not encrypted on the network. For anything beyond a trusted LAN use an SSH tunnel (`ssh -L 8080:127.0.0.1:8080 host`, with logscrub on loopback) or a TLS reverse proxy.
- **Host check** (against DNS rebinding): requests whose `Host` header is not the address it listens on (or `localhost`) get 403.
- **Origin and Content-Type check** (against cross-site requests): the scrub endpoint only accepts JSON posted from the page itself.
- **Limits:** 10 MiB of text per request (`--max-body-bytes`; `--max-line-bytes` and `--max-private-key-lines` work as in the CLI), four requests at a time (a fifth gets 503), and timeouts. A line that cannot be scanned in bounded memory is refused (422), never passed through.

**In Docker** the server must listen on all container interfaces, so publish the port on the host's loopback only:

```sh
docker run --rm -p 127.0.0.1:8080:8080 hbenali/logscrub serve --addr 0.0.0.0:8080 --allow-remote   # prints the access token URL
```

**Accessibility.** The page is keyboard operable (the result tabs use arrow keys, Home and End), every control has an accessible name, status and errors are announced, and it follows your light or dark setting. It passes an automated axe-core audit with zero violations in light, dark and a narrow mobile layout, and all text meets WCAG AA contrast (4.5:1 or better). Automated checks do not replace testing with a screen reader, which has not been done.

Browser extensions can read page text. The log box opts out of common grammar checkers, but an extension that ignores that can still send what you paste to its own servers; use a profile without such extensions for sensitive logs.

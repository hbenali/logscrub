# Web UI

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

- **Loopback only by default.** Other addresses are refused unless you pass `--allow-remote`, and then there is still no authentication: put it behind something that has some, or don't.
- **Host check** (against DNS rebinding): requests whose `Host` header is not the address it listens on (or `localhost`) get 403.
- **Origin and Content-Type check** (against cross-site requests): the scrub endpoint only accepts JSON posted from the page itself.
- **Limits:** 10 MiB of text per request (`--max-body-bytes`), four requests at a time (a fifth gets 503), and timeouts. A line that cannot be scanned in bounded memory is refused (422), never passed through.

**In Docker** the server must listen on all container interfaces, so publish the port on the host's loopback only:

```sh
docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/hbenali/logscrub serve --addr 0.0.0.0:8080 --allow-remote
```

Browser extensions can read page text. The log box opts out of common grammar checkers, but an extension that ignores that can still send what you paste to its own servers; use a profile without such extensions for sensitive logs.

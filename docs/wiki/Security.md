# Security

logscrub reads text and writes text. It makes no network connections, writes no files, and never logs or echoes what it finds: `--report` prints counts only, and error messages never contain input.

Matching uses Go's RE2 engine (linear time), so crafted input cannot cause ReDoS. Memory is bounded by `--max-line-bytes`; a line that cannot be scanned within the bound is an error, never passed through.

The optional web UI (`logscrub serve`) binds to loopback only, checks the Host and Origin of every request, sends a strict Content-Security-Policy and loads nothing from other sites; details on the [Web UI](Web-UI) page.

Limits you should know: secrets with no recognisable shape are not found, and encoded secrets (base64, URL-encoded) are not decoded. Treat the output as reviewed-by-a-human material, and use `--check` in CI as an extra safety net, not a guarantee.

To report a vulnerability, see [`SECURITY.md`](https://github.com/hbenali/logscrub/blob/HEAD/SECURITY.md).

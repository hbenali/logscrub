# logscrub: specification (MVP, v0.1)

Status: M1 (CLI core) implemented; later milestones are planned.

## 1. Purpose and positioning

logscrub masks secrets and personal data in log text so logs can be pasted into a bug report, ticket or chat.

`some-command | logscrub > clean.log`

Similar tools exist (Python `safelog`, `redactcli`, `ShareClean`; npm `logscrub`; browser-only redactors). logscrub differentiates on:

1. **Linear-time matching.** Go's RE2 `regexp`; hostile input cannot trigger ReDoS.
2. **Measured false positives.** A "must not change" corpus runs in CI; a detector that mangles it does not ship.
3. **CI-friendly.** `--check` (exit 1 if anything would be masked) and `--report` (counts per detector, never the secrets).
4. **One engine, two front ends.** The CLI and a local web UI share the same detector code (the UI calls the Go process; no JS reimplementation).
5. **Single static binary**, Docker image, GitHub release.

Non-goals: finding secrets in git history (gitleaks/trufflehog do that), verifying whether a secret is live, structured-log pipeline integration (no logrus/slog hooks in v0.1), guaranteeing that nothing sensitive remains (see section 9).

## 2. CLI

```
logscrub [flags] [file ...]      # no files: read stdin; "-" means stdin
```

| Flag | Meaning |
|---|---|
| `--mode marker\|pseudonym` | default `marker` |
| `--key-file PATH` / env `LOGSCRUB_KEY` | HMAC key for pseudonym mode (see 4). Never accepted as a plain argument (visible in `ps`). |
| `--config PATH` | rules file (see 5). Default: none; built-in detectors only. |
| `--enable a,b` / `--disable a,b` | detector ids |
| `--check` | write nothing to stdout; exit 1 if any match, 0 if none |
| `--report` | print per-detector counts to stderr (or stdout with `--check`); no match text |
| `--max-line-bytes N` | default 1 MiB, see 6 |
| `--list-detectors` | print ids and one-line descriptions |
| `--version` | version and commit |

Exit codes: 0 ok, 1 `--check` found matches, 2 usage or config error, 3 I/O error. Errors go to stderr and never contain input text.

Output is deterministic: same input, flags, config and key give byte-identical output. Line endings (LF/CRLF) and a missing final newline are preserved.

## 3. Detectors (built-in ids)

Each detector has: id, regex (RE2), optional validator (post-match check), optional "group to mask" (mask only the secret part, keep the key name), and a confidence tier. Tier `high` is on by default; tier `medium` is on by default but documented; tier `low` is off by default.

| id | Matches | Notes |
|---|---|---|
| `aws-access-key` | `AKIA/ASIA/...` + 16 chars | high |
| `aws-secret-key` | 40-char base64 only when preceded by a key name like `aws_secret_access_key` | context required |
| `github-token` | `ghp_ gho_ ghu_ ghs_ ghr_ github_pat_` | high |
| `gitlab-token` | `glpat-...` | high |
| `slack-token` | `xox[abprs]-...`, webhook URLs | high |
| `stripe-key` | `sk_live_ rk_live_ pk_live_` (not `*_test_`) | high |
| `jwt` | three base64url parts, header decodes to JSON with `alg` | validator |
| `private-key` | `-----BEGIN ... PRIVATE KEY-----` through `END` (multi-line, see 6) | high |
| `bearer-token` | `Authorization: Bearer X`, also `Basic X`; masks X | high |
| `url-credentials` | `scheme://user:pass@host`; masks user:pass | high |
| `kv-secret` | `password= secret= token= api_key= apikey=` (case-insensitive, `=`/`:`, quoted or bare) and JSON `"password": "..."` | masks value only |
| `email` | RFC-pragmatic address | medium |
| `ipv4` | dotted quad, octets 0-255, not part of a longer dotted number (versions, OIDs) | medium; allow-list loopback/private ranges optional |
| `ipv6` | full and compressed forms | medium |
| `credit-card` | 13-19 digits, optional separators, **Luhn-valid** and known IIN prefix | validator |
| `phone` | E.164 (`+` and 8-15 digits) only | low (off by default; national formats too ambiguous) |

Adding a detector requires: tests with positives, a negative list, and no new diffs on the must-not-change corpus.

## 4. Modes

**marker:** replace each match with `[REDACTED:<id>]`; for `kv-secret`/`bearer-token`/`url-credentials` only the secret part is replaced, so `password=hunter2` becomes `password=[REDACTED:kv-secret]`.

**pseudonym:** replace with `[<id>:<tag>]` where `tag = base32(HMAC-SHA256(key, id || 0x00 || match))[:8]`. The same value maps to the same tag across the file and across runs with the same key, so logs stay debuggable ("same IP hit the endpoint 40 times") without revealing the value.

- Key: from `--key-file` or `LOGSCRUB_KEY`. If neither is given, a random per-run key is generated and discarded (tags are stable within one run only). Document that a *shared* key lets anyone with it confirm guesses for low-entropy values (IPs, emails), so the key is secret and per-use.
- 8 base32 chars (40 bits) is for readability, not security; documented.
- Secrets (tokens, keys, passwords) always use marker output even in pseudonym mode, because correlating them has no debugging value and a tag is a needless fingerprint. Only `email`, `ipv4`, `ipv6` and user-defined rules with `pseudonym = true` are pseudonymized.

## 5. Config file (TOML)

```toml
# logscrub.toml
disable = ["phone"]
enable  = ["phone-e164"]

[[allow]]            # never mask matches equal to / matching these
exact = ["127.0.0.1", "noreply@example.com"]
regex = ['^10\.0\.']

[[rule]]             # custom detector
id        = "internal-ticket-token"
regex     = 'TKT-[A-Z0-9]{16}'
group     = 0
pseudonym = false
```

Parsed strictly (unknown keys are errors). Custom regexes are compiled with RE2, so they are linear-time too. The config is data, not code. Allow-list applies after detection, before replacement. A TOML parser is the only third-party dependency considered (or a small in-repo parser if the subset stays tiny; decide at implementation).

## 6. Streaming, limits, multi-line

- Read with a bounded buffer; process line by line; memory is O(longest permitted line), not O(file).
- **Long lines:** lines over `--max-line-bytes` are processed in overlapping windows (overlap >= the longest detector's max match length) so a secret split on a window boundary is still caught. Never silently pass an oversized line through unscanned; if a window cannot be scanned, fail with exit 3 rather than emit unmasked data.
- **Multi-line:** only `private-key` spans lines. It is handled by a small state machine (BEGIN line starts masking, END line stops it, the whole block becomes one marker). A BEGIN without END within `--max-private-key-lines` (default 200) is masked up to that limit and reported, never passed through.
- Detectors run per line in a fixed priority order; overlapping matches are resolved by the earlier start, then the longer match, then priority. Replacement is a single pass over the original line (no re-scanning replaced text).
- Binary or invalid UTF-8 is processed as bytes; masking must not corrupt unrelated bytes.
- No network access in the CLI at all (no update checks, no telemetry).

## 7. Web UI (phase 2, after the CLI is solid)

`logscrub serve --addr 127.0.0.1:8080`: paste or drop a log, see highlighted would-be matches by detector, toggle detectors, download the cleaned text.

- Binds to loopback by default; binding elsewhere needs an explicit flag and prints a warning.
- Assets embedded in the binary (`embed`); **no CDN, fonts, analytics or external requests**.
- Strict CSP: `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`. Plus `X-Content-Type-Options`, `Referrer-Policy: no-referrer`.
- Text is POSTed to the local process, processed in memory, returned; **never written to disk**, never logged (request bodies excluded from access logs). Body size limit (default 10 MiB) and timeouts.
- CSRF/DNS-rebinding: check `Host` against the bind address and reject cross-origin requests (`Origin` check), since a local server is reachable from any web page the user visits.
- The highlighted preview returns offsets and detector ids, and the browser renders the text itself (textContent only, no innerHTML) to avoid XSS from log content.

## 8. Threat model

| Asset | Threat | Mitigation |
|---|---|---|
| Secrets in input | leaked via our own output, errors, logs or crash dumps | errors never include input text; no logging of matches; `--report` counts only; tests assert this |
| CPU/memory | hostile log (ReDoS, huge line, many matches) | RE2 only; line/window limits; bounded memory; fuzz tests |
| Output integrity | a split or encoded secret passes through | window overlap; documented limits (section 9); `--check` for CI gating |
| Web UI | page-to-localhost attack, XSS from log content, exfiltration | loopback bind, Host/Origin checks, CSP, textContent-only, no outbound requests |
| Pseudonym key | reversal of low-entropy values by brute force | key secret and per-use; docs warn; random per-run default |
| Supply chain | compromised dependency or release | minimal deps, SHA-pinned actions, signed tags, checksums attested, Trivy/CodeQL/Scorecard |
| Config | config injects catastrophic behavior | no code execution in config; RE2 only; strict parse |

## 9. What logscrub does not promise

Regex detection cannot catch secrets with no recognizable shape (a password in prose, a random 20-char string with no key name), names, free-text identifiers, or secrets that are encoded (base64 of a token, URL-encoded). Output must still be reviewed before sharing publicly. `--check` in CI lowers risk; it does not eliminate it. This goes in the README and `--help`.

## 10. Testing strategy

1. **Unit tests per detector:** positives, negatives, boundaries (start/end of line, adjacent punctuation, quotes).
2. **Must-not-change corpus** (`testdata/clean/`): realistic nginx/apache access logs, syslog, JSON logs, Java/Python/Go stack traces, build output, with version strings, hashes (git SHAs, sha256), UUIDs, timestamps, build IDs, hex dumps. Golden test: output equals input byte for byte. A new false positive is a bug with a corpus entry.
3. **Must-change corpus** (`testdata/dirty/` plus golden outputs): each detector, in each mode.
4. **Property tests:** idempotent in marker mode (running twice equals once); line count and line endings preserved; pseudonym output stable for equal inputs.
5. **Fuzzing** (`go test -fuzz`): arbitrary bytes never panic, never exceed memory bound, and never emit text that still matches a high-tier detector (the "no leak after scrub" invariant).
6. **Chunking tests:** same result for any read-buffer size (frontail lesson: an error message split across chunks).
7. **End to end:** build the real binary, pipe real logs through it, check exit codes of `--check`; for the UI, drive a real browser (CSP violations in the console, no external requests in the network panel, XSS payload in a log line renders inert).
8. **Security fixes** ship with a regression test seen failing first.

## 11. Layout (planned)

```
cmd/logscrub/main.go        flags, wiring, version vars
internal/detect/            detector definitions, validators (Luhn, JWT)
internal/scrub/             streaming engine, window/overlap, modes
internal/config/            TOML rules
internal/serve/             web UI server (phase 2)
internal/serve/web/         embedded static assets
testdata/clean|dirty/
```

## 12. Milestones

1. **M1 (CLI core):** engine, marker mode, high-tier detectors, `--check`, `--report`, corpora, fuzz, CI green.
2. **M2:** pseudonym mode, config file, remaining detectors, docs and wiki.
3. **M3:** first signed tag and release (after debugging the Go workflows on a throwaway repo), Docker image.
4. **M4:** web UI.

## 13. Open questions

- TOML dependency vs in-repo parser.
- Default handling of private/loopback IPs (mask all, or allow-list by default)?
- Whether to add JSON-aware masking by key name (`"token": ...` is covered by `kv-secret`; deeper structure handling deferred).
- Frontail integration: a "sanitized download" would shell out to the binary or call `serve`; decide after M2.

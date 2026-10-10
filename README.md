# logscrub

Mask secrets and personal data in logs so they can be shared safely (bug reports, tickets, chat).

```sh
some-command | logscrub > clean.log
logscrub app.log                 # files work too
logscrub --check app.log         # CI gate: exit 1 if anything would be masked
logscrub --report app.log        # counts per detector, never the matched text
```

```text
$ printf 'GET /cb?access_token=abc123\nconnect postgres://app:s3cret@db/x\n' | logscrub
GET /cb?access_token=[REDACTED:kv-secret]
connect postgres://[REDACTED:url-credentials]@db/x
```

## What it masks (v0.1)

AWS access and secret keys, GitHub / GitLab / Slack / Stripe tokens, JWTs, PEM private keys (including multi-line blocks), `Authorization` headers and long Bearer tokens, `user:password@` in URLs, and `password=` / `token=` / `"api_key": "..."` style pairs. `logscrub --list-detectors` lists them. Emails, IPs, card numbers, stable pseudonyms and a config file are planned (see [docs/SPEC.md](docs/SPEC.md)).

## Why another one

- **Linear-time matching.** Go's RE2 engine: hostile input cannot trigger ReDoS.
- **Measured false positives.** A "must not change" corpus of realistic logs runs in CI; `max_tokens=100` and `ssh://git@host` stay untouched.
- **Bounded memory, fail closed.** Streams line by line; a line it cannot scan safely is an error (exit 3), never passed through.
- **No network, no files written, never echoes what it finds.** Reports and errors contain counts and ids only.
- One static binary, a distroless Docker image, signed releases.

## Install

Binaries on [Releases](https://github.com/hbenali/logscrub/releases); `docker run --rm -i ghcr.io/hbenali/logscrub < app.log`; or `go install github.com/hbenali/logscrub/cmd/logscrub@latest`.

## Limits

Regex detection cannot find secrets with no recognisable shape (a password in prose, an unlabelled random string) or encoded ones (base64, URL-encoded). Review the output before sharing it publicly; `--check` in CI lowers the risk, it does not remove it.

Docs: [wiki](https://github.com/hbenali/logscrub/wiki), [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md). MIT licensed.

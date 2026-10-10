# logscrub

Mask secrets and personal data in logs

## Commands

```sh
go build ./cmd/logscrub                   # build the binary
go vet ./... && go test -race -cover ./... # vet + tests (CI runs the same)
golangci-lint run                         # lint (config in .golangci.yml)
go test ./internal/scrub -run '^$' -fuzz FuzzScrub -fuzztime 60s   # fuzz the engine
some-command | go run ./cmd/logscrub      # try it
```

Run the tests, linter and type/vet checks before committing; CI runs them on every push.

## Layout

- `cmd/logscrub/main.go`: flags, exit codes, wiring only (detector selection, pseudonym key handling).
- `internal/serve/`: the web UI server (`serve.go`) and its embedded page (`web/`). Security checks live in `protect`, `checkOrigin` and `handleScrub`; each has a test that fails without it.
- `internal/config/`: strict TOML rules file (enable/disable, allow-list, custom RE2 rules).
- `internal/detect/`: the detectors (RE2 patterns + validators). Adding one means positives, negatives and a clean-corpus check.
- `internal/scrub/`: the streaming engine (line reader, windowing for huge lines, overlap resolution, private-key blocks).
- `testdata/clean/`: the **must-not-change corpus**; `docs/SPEC.md`: the spec and milestones (M1 CLI core, M2 pseudonyms/config/PII/prefilter and M4 web UI done).

## Conventions and gotchas

- **Test secrets are built from string pieces** (`"sk" + "_live_" + ...`) so GitHub push protection and secret scanners don't flag the repo. Don't put realistic tokens in testdata files.
- **Window cuts use the whole regexp match, not the masked group.** Cutting between `password=` and its value left a value no pattern recognises (a real leak, found by the offset sweep test).
- **A line that can't be scanned is an error (exit 3), never passed through.** Error messages must not quote input.
- **Detectors need a false-positive trap in `testdata/clean/`** (`max_tokens=100`, `ssh://git@host`, `refresh token: refused`). Keys must *end* in the secret word; `name: value` only on YAML-looking lines.
- **Throughput is ~10 MB/s** thanks to the per-detector prefilter (`Hints`/`Pre`). Every detector should declare hints; `TestPrefilterDoesNotChangeOutput` and the fuzz target compare output with and without the prefilter, so a wrong hint fails CI. Hints for case-insensitive patterns must be lowercase.
- **RE2 has no lookaround:** use a `Check` hook for "not part of a longer token" instead of consuming boundary characters in the regexp (that breaks adjacent matches).
- **Web UI is reachable from every page the user visits.** Keep Host, Origin, Content-Type, size and concurrency checks and the strict CSP; never add `unsafe-inline`, a CDN, `innerHTML` or inline script/style (a test greps the assets). The engine reports match offsets via `scrub.Options.Observe` (UTF-8 byte offsets; applying the spans to the input must reproduce the output, which the fuzz target checks).
- **Accessibility:** after UI changes run axe-core in headless Chrome (light, dark, mobile, results, token form); the last audit found 0 violations. `TestFormControlsHaveAccessibleNames` guards the fixes (labels, landmarks, tab keys). Never rely on `title`/`placeholder` as a label.
- **Test the UI in a real browser after any change to `internal/serve/web`**: highlights with multibyte text, an XSS payload line, CSP violations via a `securitypolicyviolation` listener plus a second local server that records requests, and the download contents.
- **Pseudonym mode:** only detectors with `Pseudonym: true` get HMAC tags; secrets keep fixed markers (a stable tag on a secret is a fingerprint). Keys come from a file or `LOGSCRUB_KEY`, never argv.
- Commit with `GIT_CONFIG_GLOBAL=$HOME/.gitconfigp`, no trailers.
- **Security tests fail without the fix.** Every auth/injection/resource-limit fix ships with a regression test that was seen failing first.
- **Verify behaviour end to end, not just in unit tests.** Several real bugs here (an auth bypass, inverted flag defaults, an error message split across chunks) passed the unit tests; they surfaced only when running the real binary/server and a browser.
- **Library upgrades change semantics silently.** After a major bump, run the real program and compare behaviour, not just the test suite.
- **Don't trust a helper's name.** E.g. a "signed cookie" parser returns unsigned values unchanged; read what a function does for the *invalid* case.
- Keep dependencies minimal; prefer a small in-repo helper over a new package.

## Security checks and GitHub config

- Explicit CodeQL (`.github/workflows/codeql.yml` + `.github/codeql/codeql-config.yml`: the project language plus the Actions workflows, `security-extended`). GitHub's *default setup* for code scanning must be switched off, because advanced and default setup can't coexist.
- Trivy (`.github/workflows/trivy.yml`, `.trivyignore.yaml`): exceptions need a written reason.
- OpenSSF Scorecard (`.github/workflows/scorecard.yml`). Process findings that don't apply to a solo-maintained repo (code review, fuzzing, best-practices badge) are dismissed with a comment, not left open.
- Every third-party GitHub Action is pinned to a **commit SHA** (version in a comment) and the repo enforces it (`sha_pinning_required`); Dependabot keeps them current. Workflow tokens are read-only by default; give a job write access only if it needs it, with a comment saying why.
- `SECURITY.md` policy; GitHub private vulnerability reporting enabled; issue and PR templates in `.github/`.
- **Always check open Dependabot and code-scanning alerts before and after releases:**

  ```sh
  gh api repos/hbenali/logscrub/dependabot/alerts -q '[.[]|select(.state=="open")]|length'
  gh api 'repos/hbenali/logscrub/code-scanning/alerts?state=open' -q length
  ```

## Releasing

See `RELEASING.md`. Summary: signed tag (`git tag -s`); the tag workflow builds everything and creates a **draft** release (releases are immutable once published, so assets can't be added later); then publish it with notes: `gh release edit X.Y --title X.Y --notes-file notes.md --draft=false`.

Lessons: don't remove `contents: write` from a workflow job that pushes commits (a "least privilege" cleanup broke a release step); a workflow change that only runs on tags can't be tested without releasing, so keep such changes small and re-check them on the next release.

## Docs

`docs/wiki/` is the source of truth for the GitHub wiki (published by `.github/workflows/wiki.yml` on every change; edits made in the wiki UI are overwritten). GitHub only creates the wiki repository when its first page is created once in the web UI.

# Contributing

Setup: `go build ./cmd/logscrub && go vet ./... && go test -race ./...`. The code is small: `internal/detect` (patterns and validators), `internal/scrub` (streaming engine), `cmd/logscrub` (flags). The design is in [`docs/SPEC.md`](https://github.com/hbenali/logscrub/blob/HEAD/docs/SPEC.md).

Adding a detector: positives, negatives, and a look-alike trap in `testdata/clean/` (that corpus must pass unchanged). Security fixes ship with a regression test that fails without the fix.

Releases: see `RELEASING.md` in the repository. Report vulnerabilities privately: see [Security](Security).

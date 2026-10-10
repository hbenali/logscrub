# Installation

**Standalone binary:** download the archive for your platform from [Releases](https://github.com/hbenali/logscrub/releases) (linux, macOS, windows; amd64 and arm64), verify it against `checksums.txt`, and put `logscrub` on your `PATH`.

**Docker:** `docker run --rm -i ghcr.io/hbenali/logscrub < app.log > clean.log`

**From source (Go 1.26+):** `go install github.com/hbenali/logscrub/cmd/logscrub@latest`

Usage: `some-command | logscrub > clean.log`, `logscrub app.log`, `logscrub --check app.log` (exit 1 if anything would be masked), `logscrub --report app.log` (counts per detector, never the matched text), `logscrub --list-detectors`, `logscrub --mode pseudonym app.log`, `logscrub --config logscrub.toml app.log` (see [Configuration](Configuration)).

Pattern matching can't find every secret. Review the output before sharing it.

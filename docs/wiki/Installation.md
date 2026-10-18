# Installation

**Standalone binary:** download the archive for your platform from [Releases](https://github.com/hbenali/logscrub/releases) (linux, macOS, windows; amd64 and arm64), verify it against `checksums.txt`, and put `logscrub` on your `PATH`.

**Homebrew (macOS and Linux):** `brew install hbenali/tap/logscrub` (the formula installs the binary, man page and completions).

**Ubuntu (PPA):** `sudo add-apt-repository ppa:hbenali/logscrub && sudo apt install logscrub` (22.04, 24.04 and 26.04). Launchpad builds it from source for each release, so `apt upgrade` keeps it current; it installs the binary, man page, shell completions and the licence. The packaging lives in `packaging/debian/` in the repository.

**Fedora (Copr):** `sudo dnf copr enable hbenali/logscrub && sudo dnf install logscrub` (Fedora 43, 44 and rawhide, x86_64). Copr builds it from a source RPM for each release (the spec is `packaging/rpm/logscrub.spec`), so `dnf upgrade` keeps it current; it installs the binary, man page, shell completions and the licence.

**Packages:** each release also ships `.deb`, `.rpm` and `.apk` packages (linux amd64 and arm64) that install the binary, the man page, shell completions and the licence: `sudo dpkg -i logscrub_X.Y.Z_linux_amd64.deb`, `sudo rpm -i logscrub_X.Y.Z_linux_amd64.rpm`, `apk add --allow-untrusted logscrub_X.Y.Z_linux_amd64.apk`.

**Verify a download:** check it against `checksums.txt` (`sha256sum -c --ignore-missing checksums.txt`), and verify the build provenance, which proves the file was built by this repository's release workflow: `gh attestation verify logscrub_X.Y.Z_linux_amd64.tar.gz --repo hbenali/logscrub`. From 1.1.0 every archive and package is attested individually; 1.0.0 attested `checksums.txt` only.

**Docker:** `docker run --rm -i hbenali/logscrub < app.log > clean.log` (Docker Hub; the same image is at `ghcr.io/hbenali/logscrub`)

**From source (Go 1.26+):** `go install github.com/hbenali/logscrub/cmd/logscrub@latest`

Usage: `some-command | logscrub > clean.log`, `logscrub app.log`, `logscrub --check app.log` (exit 1 if anything would be masked), `logscrub --report app.log` (counts per detector, never the matched text), `logscrub -r -i logs/` (clean a directory in place, gzip included; see [CI](CI)), `logscrub --list-detectors`, `logscrub --mode pseudonym app.log`, `logscrub --config logscrub.toml app.log` (see [Configuration](Configuration)).

**Shell completion and man page:** `logscrub completion bash|zsh|fish` prints a completion script (for example `logscrub completion bash > ~/.local/share/bash-completion/completions/logscrub`). The release archives include `logscrub.1`; copy it to a `man1` directory (or `man -l logscrub.1`).

Pattern matching can't find every secret. Review the output before sharing it.

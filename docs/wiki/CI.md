# Using logscrub in CI

`logscrub --check FILE...` writes nothing and exits **1** if anything would be masked, **0** if the files are clean, **2** on a usage error and **3** on a read or scan error. Use it as a gate before logs, artifacts or support bundles are published.

```sh
logscrub --check build.log || { echo "secrets or personal data in build.log"; exit 1; }
```

## GitHub Action

```yaml
- uses: hbenali/logscrub@1.1.1        # pin an exact release (or a commit SHA)
  with:
    files: build.log logs/*.log       # spaces or newlines; globs are expanded
    args: --config .github/logscrub.toml
    sarif-file: logscrub.sarif        # optional: also write a SARIF report
- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: logscrub.sarif
```

The action downloads the release archive for the runner (Linux, macOS or Windows; amd64 or arm64), **verifies its SHA-256 against the release's `checksums.txt`**, and runs `logscrub --check --report` on the files; the step fails if anything would be masked. `version` selects the release (`latest` by default; pin one for reproducible builds). Inputs reach the script through the environment, never by interpolation, and the version is restricted to a release number, so a workflow input cannot inject commands or change the download URL.

There is deliberately no moving `v1` tag: tags here are immutable and each one publishes a release, so pin an exact version (Dependabot can bump it).

## pre-commit

```yaml
repos:
  - repo: https://github.com/hbenali/logscrub
    rev: 1.1.1
    hooks:
      - id: logscrub
        # args: [--config, .github/logscrub.toml]
```

pre-commit builds logscrub from source, so Go must be installed. The hook fails the commit if a staged text file would be masked and prints counts per detector, never the text.

## Reports

`--report` prints counts per detector (never the matched text). `--report-format json` and `sarif` also list where each match is:

```sh
logscrub --check --report --report-format json build.log      # to stdout with --check
logscrub --check --report --report-format sarif build.log > logscrub.sarif
```

- **JSON:** `total`, `counts`, and `findings` with `file`, `line`, `column` (1-based, counted in bytes), `byte_offset`, `byte_length` and `detector` (plus `end_line` for private key blocks that span lines). Listing is capped at 100,000 findings; `findings_truncated` says so and the counts stay exact.
- **SARIF 2.1.0:** one rule per detector, one result per match with the line and byte range. GitHub code scanning accepts it (`github/codeql-action/upload-sarif`), so findings show up as alerts on the file and line.

Reports never contain the text that was found, so they are safe to upload as CI artifacts. The file name is the path you passed (`stdin` for standard input).

## Writing the cleaned file

`logscrub -o clean.log app.log` writes the cleaned text to a file: atomically (a failed run never leaves a half-written file or replaces the old one), with mode 0600, and it refuses to overwrite a file it is reading. The shell equivalent, `logscrub app.log > clean.log`, works too; `-o` is for when you want those guarantees.

## Cleaning files in place, directories and gzip

- `logscrub -i app.log other.log` rewrites each file with its cleaned text. Every file is replaced atomically (temporary file in the same directory, then rename) and keeps its permissions; a file with nothing to mask is not touched at all (same mtime, no backup). `--backup-suffix .bak` keeps the original of each *changed* file as `app.log.bak` (a hard link; an existing backup is never overwritten, the run fails for that file instead). The backup still holds the secrets, so delete it or keep it out of anything you publish. A file that cannot be scanned is reported and left as it was; the other files are still processed and the exit code is 3. `-i` cannot be combined with `--check` or `-o`, and cannot rewrite standard input.
- `-r` / `--recursive` descends into the directories you pass. It skips symbolic links (they could point outside the tree), `.git`/`.hg`/`.svn`, files ending in the backup suffix, and binary files (a NUL byte in the first 8000 bytes; a count is printed). `--include '*.log,*.txt'` limits it to matching file names and `--exclude node_modules` skips matching files or directories. Files named on the command line are always processed.
- **gzip** input is detected by its content (also on stdin) and decompressed on the fly in constant memory. With `-i` a `.gz` file stays gzip; `-o clean.log.gz` writes gzip; on standard output you get plain text. zip, bzip2 and zstd archives are not supported.

```sh
logscrub -r -i --exclude node_modules --include '*.log,*.log.gz' /var/log/myapp
logscrub --check -r --report support-bundle/      # gate: nothing is written
```

## Config in CI

logscrub reads a per-user config (`$XDG_CONFIG_HOME/logscrub/config.toml`, if it exists and is not world-writable) and an explicit `--config FILE`. It deliberately does **not** look for a config in the current directory: an allow-list in an untrusted checkout could make logscrub leak what it was asked to mask. In CI, pass your committed config explicitly:

```sh
logscrub --config .github/logscrub.toml --check build.log
```

Use `--no-config` to ignore the per-user file.

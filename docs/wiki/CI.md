# Using logscrub in CI

`logscrub --check FILE...` writes nothing and exits **1** if anything would be masked, **0** if the files are clean, **2** on a usage error and **3** on a read or scan error. Use it as a gate before logs, artifacts or support bundles are published.

```sh
logscrub --check build.log || { echo "secrets or personal data in build.log"; exit 1; }
```

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

## Config in CI

logscrub reads a per-user config (`$XDG_CONFIG_HOME/logscrub/config.toml`, if it exists and is not world-writable) and an explicit `--config FILE`. It deliberately does **not** look for a config in the current directory: an allow-list in an untrusted checkout could make logscrub leak what it was asked to mask. In CI, pass your committed config explicitly:

```sh
logscrub --config .github/logscrub.toml --check build.log
```

Use `--no-config` to ignore the per-user file.

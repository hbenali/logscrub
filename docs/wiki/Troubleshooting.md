# Troubleshooting

**Something sensitive was not masked.** logscrub recognises secrets by shape (tokens, keys, `password=` style pairs). A password in prose or an unlabelled random string has no shape. Open an issue with a *fake* example of the line.

**A private IP or address I want to keep was masked.** Add it to an `[[allow]]` list in the [config file](Configuration).

**Something harmless was masked.** Run `logscrub --report` to see which detector fired, then turn it off with `--disable <id>` (ids: `--list-detectors`) and open an issue with the line; false positives are bugs.

**`logscrub: scrub: line too long to scan safely` (exit 3).** One line was far longer than `--max-line-bytes` (default 1 MiB) and could not be scanned in bounded memory, so nothing from it was written. Raise `--max-line-bytes` or split the line.

**`warning: private key block longer than 200 lines: the rest of it is not masked`.** A `-----BEGIN ... PRIVATE KEY-----` block never closed (or is unusually long), so logscrub masked up to the limit and stopped. Raise `--max-private-key-lines` if the block is genuine, and check the text after the marker.

**Exit codes:** 0 ok, 1 `--check` found something, 2 usage error, 3 read or scan error.

# Configuration

Everything works without a config file. Add one with `--config logscrub.toml` (or put one at `$XDG_CONFIG_HOME/logscrub/config.toml`, e.g. `~/.config/logscrub/config.toml`, which is read automatically unless you pass `--no-config`; logscrub never reads a config from the current directory, see [Using it in CI](CI)) for an allow-list, custom rules, or to change which detectors run.

```toml
# logscrub.toml
enable  = ["phone"]          # detectors that are off by default
disable = ["credit-card"]

[[allow]]                    # never mask these
exact = ["noreply@example.com", "10.0.0.1"]   # compared case-insensitively
regex = ['^192\.168\.']                       # RE2, unanchored: add ^ and $ yourself

[[rule]]                     # a custom detector
id        = "ticket-token"   # lowercase letters, digits, dashes; must not clash with a built-in
regex     = 'TKT-([A-Z0-9]{16})'
group     = 1                # which group to mask; 0 = the whole match
pseudonym = false            # true: stable tag in pseudonym mode
```

The file is parsed strictly: an unknown key or an invalid regexp is an error (exit 2). Patterns use Go's RE2 engine, so they run in linear time. Precedence for enable/disable: built-in defaults, then the file, then command-line flags.

## Pseudonym mode

`logscrub --mode pseudonym --key-file key.txt app.log` replaces emails and IP addresses with tags such as `[email:k3x9p2qa]`, derived from HMAC-SHA256 of the value with your key. The same value always gets the same tag (case-insensitive for emails, format-insensitive for IPv6), so you can still see that one client hit an endpoint 40 times.

- The key must be at least 16 bytes. Pass it as a file (`--key-file`) or in `LOGSCRUB_KEY`; never on the command line (it would show in `ps`). Without a key, a random one is used and tags are stable within that run only.
- Tags are for readability, not secrecy: anyone with the key can confirm a guess for a low-entropy value such as an IP address. Keep the key private and use a different one per audience.
- Secrets (tokens, passwords, keys) always use `[REDACTED:id]`, never a tag.

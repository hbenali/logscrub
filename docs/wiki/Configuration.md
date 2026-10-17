# Configuration

Everything works without a config file. Add one with `--config logscrub.toml` (or put one at `$XDG_CONFIG_HOME/logscrub/config.toml`, e.g. `~/.config/logscrub/config.toml`, which is read automatically unless you pass `--no-config`; logscrub never reads a config from the current directory, see [Using it in CI](CI)) for an allow-list, custom rules, or to change which detectors run.

```toml
# logscrub.toml
enable  = ["phone"]          # detectors that are off by default
disable = ["credit-card"]
mask_keys = ["pin", "otp"]   # also mask the value of keys ending in these names

[[allow]]                    # never mask these
exact = ["noreply@example.com", "10.0.0.1"]   # compared case-insensitively
regex = ['^192\.168\.']                       # RE2, unanchored: add ^ and $ yourself

[[rule]]                     # a custom detector
id        = "ticket-token"   # lowercase letters, digits, dashes; must not clash with a built-in
regex     = 'TKT-([A-Z0-9]{16})'
group     = 1                # which group to mask; 0 = the whole match
pseudonym = false            # true: stable tag in pseudonym mode
```

### `mask_keys`: your own key names

The built-in `kv-secret` detector only knows keys that end in password, secret, token, api key and similar words. `mask_keys` adds yours: the value is masked in `pin=1234`, in JSON (`{"user_pin": "9876", "otp": 654321}`, strings and numbers, also pretty-printed) and in YAML-looking lines (`- otp: 112233`). A key matches when it **ends in** a listed name, case-insensitively, so `pin` covers `user_pin` and `userPin` but not `pincode` or `max_pin_tries`, and it also covers `spin`; pick names that are specific. Empty values, `null`, `true`/`false` and template placeholders (`${OTP}`) are left alone, and prose such as `enter your pin: now` is not touched. Names are letters, digits, `.`, `_` and `-` (at most 64 characters, at most 200 names). The findings are reported as `[REDACTED:custom-key]`, and `--disable custom-key` turns the list off for one run.

For anything more specific, such as a value that depends on its path in the JSON document, use a `[[rule]]` with a regexp.

The file is parsed strictly: an unknown key or an invalid regexp is an error (exit 2). Patterns use Go's RE2 engine, so they run in linear time. Precedence for enable/disable: built-in defaults, then the file, then command-line flags.

## Pseudonym mode

`logscrub --mode pseudonym --key-file key.txt app.log` replaces emails and IP addresses with tags such as `[email:k3x9p2qa]`, derived from HMAC-SHA256 of the value with your key. The same value always gets the same tag (case-insensitive for emails, format-insensitive for IPv6), so you can still see that one client hit an endpoint 40 times.

- The key must be at least 16 bytes. Pass it as a file (`--key-file`) or in `LOGSCRUB_KEY`; never on the command line (it would show in `ps`). Without a key, a random one is used and tags are stable within that run only.
- Tags are for readability, not secrecy: anyone with the key can confirm a guess for a low-entropy value such as an IP address. Keep the key private and use a different one per audience.
- Secrets (tokens, passwords, keys) always use `[REDACTED:id]`, never a tag.

### Reversing it: `--map-file` and `logscrub restore`

Add `--map-file map.json` to remember which text each tag stands for, and put it back later with `logscrub restore`:

```sh
logscrub --mode pseudonym --map-file map.json app.log > for-vendor.log
# the vendor answers: "[email:k3x9p2qa] is failing from [ipv4:tlyzhmno]"
echo '[email:k3x9p2qa] is failing' | logscrub restore --map-file map.json
logscrub restore --map-file map.json -i notes.txt     # also -o FILE and files
```

- **The map file contains the personal data you removed.** It is written atomically with mode 0600, `restore` refuses a group- or world-writable one, and it must never be sent along with the cleaned log. Treat it like the original log.
- Only pseudonymised kinds (emails, IPs, and any `pseudonym = true` rule of yours) are recorded. Secrets are never written to the map and cannot be restored: they are gone by design.
- The map accumulates across runs, so tags from several runs can be restored with one file. The first spelling seen wins when two spellings share a tag (`Bob@X.org`, `bob@x.org`).
- With `-i` or `-o` the map is written before anything is replaced. `-r` never scrubs the map file itself.
- Tags that are not in the map are left alone and counted in a warning. The map is limited to 2 million distinct values per file.

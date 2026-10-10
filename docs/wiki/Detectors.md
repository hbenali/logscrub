# Detectors

`logscrub --list-detectors` prints the same list. "Tag" means the detector gets stable HMAC tags in `--mode pseudonym`; everything else always uses `[REDACTED:id]`, because a stable tag on a secret would be a fingerprint. Turn any detector off with `--disable ID` or `disable = [...]` in the [config file](Configuration); add your own with `[[rule]]`.

## Secrets and tokens

| id | what it finds | tag |
| --- | --- | --- |
| `aws-access-key` | AWS access key id (AKIA/ASIA/... + 16 characters) |  |
| `aws-secret-key` | 40-character AWS secret key after an aws_secret_access_key style name |  |
| `github-token` | GitHub token (ghp_, gho_, ghu_, ghs_, ghr_, github_pat_) |  |
| `gitlab-token` | GitLab personal access token (glpat-) |  |
| `slack-token` | Slack token (xox?-) or incoming webhook URL |  |
| `stripe-key` | Stripe live key (sk_live_, rk_live_, pk_live_) |  |
| `dockerhub-token` | Docker Hub access token (dckr_pat_) |  |
| `anthropic-key` | Anthropic API key (sk-ant-) |  |
| `openai-key` | OpenAI API key (sk-proj-, sk-svcacct-, sk-admin-, legacy sk-) |  |
| `google-api-key` | Google API key (AIza...) |  |
| `npm-token` | npm access token (npm_) |  |
| `pypi-token` | PyPI upload token (pypi-) |  |
| `sendgrid-key` | SendGrid API key (SG.) |  |
| `huggingface-token` | Hugging Face access token (hf_) |  |
| `shopify-token` | Shopify access token (shpat_, shpca_, shppa_, shpss_) |  |
| `digitalocean-token` | DigitalOcean token (dop_v1_, doo_v1_, dor_v1_) |  |
| `vault-token` | HashiCorp Vault token (hvs.) |  |
| `age-key` | age secret key (AGE-SECRET-KEY-1) |  |
| `telegram-token` | Telegram bot token (123456789:AA...) |  |
| `azure-storage-key` | Azure storage AccountKey= in a connection string |  |
| `jwt` | JSON Web Token (header must decode to JSON) |  |
| `private-key` | PEM private key block (may span lines) |  |
| `url-credentials` | user:password in a URL (scheme://user:pass@host) |  |
| `bearer-token` | credential in an Authorization header, or a long Bearer token |  |
| `cookie` | value of a Cookie / Set-Cookie header or field (name=value pairs) |  |
| `kv-secret` | value of password=, token=, api_key=, "secret": ... style pairs |  |

## Personal data

| id | what it finds | tag |
| --- | --- | --- |
| `email` | email address | yes |
| `ipv4` | IPv4 address (loopback and 0.0.0.0 are left alone) | yes |
| `ipv6` | IPv6 address (::1 and :: are left alone) | yes |
| `credit-card` | payment card number (Luhn-valid, known issuer prefix) |  |
| `iban` | IBAN bank account number (mod-97 checked) | yes |
| `home-path` | user name in /home/NAME, /Users/NAME or C:\Users\NAME (role names such as runner are left alone) | yes |
| `phone` | phone number in international format (+ and 8-15 digits) |  |

## Opt-in (off by default; enable with `--enable ID` or in the config)

| id | what it finds | tag |
| --- | --- | --- |
| `us-ssn` | US social security number (123-45-6789) |  |
| `mac-address` | hardware (MAC) address | yes |
| `high-entropy` | long random-looking string with no label (letters and digits, entropy > 4), expect false positives |  |

## False positives and what is left alone

Every detector has look-alike traps in the test corpus: version strings (`Chrome/126.0.0.0`), timestamps, MAC addresses (unless `mac-address` is on), `ssh://git@host`, `icon@2x.png`, `scikit-learn`, role accounts in home paths (`/home/runner`), hashes and UUIDs. If something harmless is masked, `logscrub --report` shows which detector fired; please open an issue with a fake example of the line.

The opt-in `high-entropy` detector flags long random-looking strings with no label. It is deliberately conservative (it ignores hashes, UUIDs, slugs and words) but it will still hit things like base64 payloads, so review its output.

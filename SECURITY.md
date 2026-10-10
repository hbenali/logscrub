# Security policy

## Supported versions

Only the latest release receives security fixes. Please upgrade before reporting an issue you found in an older version.

| Version | Supported |
| --- | --- |
| Latest release ([GitHub releases](https://github.com/hbenali/logscrub/releases/latest)) | yes |
| Anything older | no |

## Reporting a vulnerability

**Please don't open a public issue or pull request for a security problem.** Report it privately, either:

- through GitHub: **[Report a vulnerability](https://github.com/hbenali/logscrub/security/advisories/new)** (private vulnerability reporting), or
- by email to **contact@hbenali.ovh** with the subject `logscrub security`.

Include what you can of:

- the affected version and how it is run (install method, flags, environment);
- what an attacker can do and what they need (network access, valid credentials, ...);
- steps or a proof of concept to reproduce it.

## What to expect

- an acknowledgement within **3 working days**;
- an assessment and, if it is a vulnerability, a fix plan within **10 working days**;
- a fix released as soon as it is ready and verified, with the release notes describing the problem and how to mitigate it, crediting you if you wish;
- coordinated disclosure: please keep details private until a fixed release is available.

This is a volunteer-maintained project; there is no bug bounty.

## Scope

In scope: logscrub itself, its Docker image and its release artifacts. Typical findings (in logscrub, the web UI, `action.yml`, the packages and the release artifacts): input that makes logscrub **emit a secret it should have masked** for a documented detector (a bypass), echo or log input text (including in errors or reports), consume unbounded CPU or memory (ReDoS is excluded by design: RE2), or cross-origin, injection or authentication attacks against the web UI (including its access token), or a way to make the GitHub Action run unintended commands or install an unverified binary. Secrets with no recognisable shape are a documented limitation, not a vulnerability.

Out of scope: issues that require an already-compromised host; missing hardening with no concrete impact; vulnerabilities in third-party dependencies with no demonstrated impact on logscrub (report those upstream; Dependabot and Trivy track them here).

## How security is checked here

CodeQL (code scanning, including the GitHub Actions workflows), Trivy (dependencies, secrets, Dockerfile and image), OpenSSF Scorecard and Dependabot run on every push and on a schedule; results are in the repository's Security tab. Release tags are signed and releases are immutable.

## Past security fixes

Fixed vulnerabilities are described in the [release notes](https://github.com/hbenali/logscrub/releases).

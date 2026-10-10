# Contributing to logscrub

Thanks for helping. Bug reports, documentation fixes and code are all welcome.

## Before you start

- **Found a bug or want a feature?** [Open an issue](https://github.com/hbenali/logscrub/issues/new/choose) using the template.
- **Security problem?** Don't open an issue or PR; follow [SECURITY.md](SECURITY.md).
- **Larger change?** Open an issue first so we can agree on the approach before you invest time.

## Development setup

```sh
git clone https://github.com/hbenali/logscrub && cd logscrub
go build ./cmd/logscrub
go vet ./... && go test -race -cover ./...
golangci-lint run    # optional locally, required in CI
```

New detectors need positive and negative tests plus a trap in `testdata/clean/`; see [docs/SPEC.md](docs/SPEC.md).

All checks must pass; CI runs them on every push and pull request. Architecture, conventions and gotchas are in [CLAUDE.md](CLAUDE.md) and the wiki's [Contributing page](https://github.com/hbenali/logscrub/wiki/Contributing).

## Making a change

1. Branch from the default branch; keep the change focused.
2. Add or update tests.
3. Update the docs in [`docs/wiki/`](docs/wiki) (published to the wiki automatically) and the README. Don't edit the wiki UI directly: it is overwritten.
4. Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `chore:`, `ci:`; `fix(security):` for security fixes), with the reason in the body.
5. Open a pull request and fill in the template. Maintainers sign release tags; signed commits are appreciated but not required.

## Principles

- **Secure by default.** Nothing may weaken the configured authentication; credentials never go on the command line when avoidable; anything that reaches a shell, a network or a file path is validated.
- **Few dependencies.** Prefer a small in-repo helper to a new package.
- **Tests for security behaviour.** A fix for auth, injection or resource limits comes with a regression test that fails without the fix.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating you agree to uphold it.

## License

Contributions are accepted under the project's license (see [LICENSE](LICENSE)).

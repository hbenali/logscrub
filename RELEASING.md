# Releasing logscrub

Releases are driven by a **signed git tag**: pushing the tag makes GitHub Actions build and publish the artifacts
(package, Docker image, binaries) and create a **draft** GitHub release with the binaries attached. Releases are
**immutable** once published (assets and the tag can't change afterwards), so the workflow never publishes by
itself: you wait for the draft, write the notes and publish it.

1. Make sure the default branch is up to date and green, and there are no open security alerts.

    ```sh
    git checkout <default-branch> && git pull --rebase origin <default-branch>
    <run tests, lint, type checks>
    gh api repos/hbenali/logscrub/dependabot/alerts -q '[.[]|select(.state=="open")]|length'
    gh api 'repos/hbenali/logscrub/code-scanning/alerts?state=open' -q length
    ```

1. Bump the version (and any version references in docs), commit and push.

    ```sh
    git commit -am "chore: bump version to X.Y.Z" && git push origin <default-branch>
    ```

1. Create a **signed** tag (`-s`; a plain `git tag` makes an unsigned one) and push it. This triggers the publish workflow.
   Never force-retag a published version: pushing a tag re-triggers publishing.

    ```sh
    git tag -s X.Y -m "X.Y" && git tag -v X.Y && git push origin X.Y
    ```

1. Wait for the workflow to finish: it creates a **draft** release with the artifacts attached. Then write the notes
   (security fixes first) and publish. The `gh` token needs the `workflow` scope.

    ```sh
    gh release edit X.Y --title X.Y --notes-file notes.md --draft=false
    ```

1. Verify the artifacts exist (package registry, Docker image, the binaries on the release) and that CI, CodeQL,
   Trivy and Scorecard are green with no open alerts.

1. If the Docker workflow bumps a pinned base-image reference automatically, check that its commit landed.

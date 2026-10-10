#!/usr/bin/env bash
# Applies the repository settings this skeleton assumes. Every call below was
# used (and verified) on hbenali/frontail. Needs `gh` logged in as an admin of
# the repository (`gh auth switch -u <owner>`).
#
# Usage: scripts/gh-setup.sh OWNER/REPO "Short description" topic1,topic2,...
set -euo pipefail

REPO="${1:?usage: gh-setup.sh OWNER/REPO \"description\" topic1,topic2}"
DESC="${2:?description required}"
TOPICS="${3:-}"

step() { printf '\n==> %s\n' "$*"; }

step "Issues and wiki on"
gh api -X PATCH "repos/$REPO" -F has_issues=true -F has_wiki=true --jq '{has_issues,has_wiki}'

step "Private vulnerability reporting"
gh api -X PUT "repos/$REPO/private-vulnerability-reporting" || true
gh api "repos/$REPO/private-vulnerability-reporting" --jq .enabled

step "Immutable releases (published releases can't be modified)"
gh api -X PUT "repos/$REPO/immutable-releases" || true
gh api "repos/$REPO/immutable-releases" --jq .enabled

step "Require every action to be pinned to a commit SHA (pin them first!)"
gh api -X PUT "repos/$REPO/actions/permissions" -F enabled=true -f allowed_actions=all -F sha_pinning_required=true --jq '.'

step "Switch GitHub's default CodeQL setup off (the advanced workflow replaces it)"
gh api -X PATCH "repos/$REPO/code-scanning/default-setup" -f state=not-configured --jq '.' || true

step "Description and topics"
gh repo edit "$REPO" --description "$DESC"
if [ -n "$TOPICS" ]; then
  args=()
  IFS=',' read -ra T <<< "$TOPICS"
  for t in "${T[@]}"; do args+=(--add-topic "$t"); done
  gh repo edit "$REPO" "${args[@]}"
fi

cat <<'MSG'

Still manual (GitHub offers no API for these):
  1. Create the wiki's first page once in the web UI (Wiki tab -> "Create the first page"), then run the
     "Publish wiki" workflow: `gh workflow run wiki.yml`.
  2. Upload docs/banner.png as the social preview: Settings -> General -> Social preview.
  3. Decide on a branch ruleset: at minimum block force-pushes and deletion of the default branch; optionally
     require the CI/CodeQL/Trivy checks for pull requests and signed commits.
MSG

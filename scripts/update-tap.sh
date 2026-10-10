#!/usr/bin/env bash
# Writes the Homebrew formula for a release into a checkout of hbenali/homebrew-tap.
# The archive checksums come from the release's own checksums.txt, so nothing
# is hashed locally and a formula can only point at published files.
#
# Usage: scripts/update-tap.sh VERSION TAP_DIR      (then review, commit and push TAP_DIR)
set -euo pipefail

version="${1:?usage: update-tap.sh VERSION TAP_DIR}"
tap="${2:?usage: update-tap.sh VERSION TAP_DIR}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "VERSION must look like 1.2.3" >&2; exit 1; }

base="https://github.com/hbenali/logscrub/releases/download/${version}"
sums="$(curl -fsSL "${base}/checksums.txt")"

sha() { # sha ARCHIVE -> its sha256 from checksums.txt
  local s
  s="$(awk -v f="$1" '$2 == f {print $1}' <<<"$sums")"
  [[ "$s" =~ ^[0-9a-f]{64}$ ]] || { echo "no checksum for $1 in checksums.txt" >&2; exit 1; }
  echo "$s"
}

mkdir -p "${tap}/Formula"
cat > "${tap}/Formula/logscrub.rb" <<RUBY
class Logscrub < Formula
  desc "Mask secrets and personal data in logs so they can be shared safely"
  homepage "https://github.com/hbenali/logscrub"
  license "MIT"

  on_macos do
    on_arm do
      url "${base}/logscrub_${version}_darwin_arm64.tar.gz"
      sha256 "$(sha "logscrub_${version}_darwin_arm64.tar.gz")"
    end
    on_intel do
      url "${base}/logscrub_${version}_darwin_amd64.tar.gz"
      sha256 "$(sha "logscrub_${version}_darwin_amd64.tar.gz")"
    end
  end

  on_linux do
    on_arm do
      url "${base}/logscrub_${version}_linux_arm64.tar.gz"
      sha256 "$(sha "logscrub_${version}_linux_arm64.tar.gz")"
    end
    on_intel do
      url "${base}/logscrub_${version}_linux_amd64.tar.gz"
      sha256 "$(sha "logscrub_${version}_linux_amd64.tar.gz")"
    end
  end

  def install
    bin.install "logscrub"
    man1.install "logscrub.1"
    bash_completion.install "completions/logscrub.bash" => "logscrub"
    zsh_completion.install "completions/_logscrub"
    fish_completion.install "completions/logscrub.fish"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/logscrub --version")
    assert_equal "password=[REDACTED:kv-secret]\n", pipe_output(bin/"logscrub", "password=hunter2\n")
    assert_match "REDACTED:email", pipe_output(bin/"logscrub", "bob@example.org\n")
  end
end
RUBY
echo "wrote ${tap}/Formula/logscrub.rb for ${version}"

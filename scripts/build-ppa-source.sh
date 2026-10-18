#!/usr/bin/env bash
# Builds the signed Debian source packages for the Launchpad PPA, one per
# Ubuntu series. The orig tarball is made once (a tag's sources plus the
# vendored modules, because the builders have no network) and reused by every
# series, as Launchpad requires.
#
# Usage: scripts/build-ppa-source.sh TAG SERIES... 
#   e.g. scripts/build-ppa-source.sh 1.2.0 jammy noble resolute
# Needs: git, go, dpkg-dev, debhelper, devscripts (debsign), and your GPG key.
# Set DEBSIGN_KEYID to the key that is registered on Launchpad.
# Output: dist/ppa/*_source.changes; upload with: dput ppa:hbenali/logscrub FILE
set -euo pipefail

tag="${1:?usage: build-ppa-source.sh TAG SERIES...}"
shift
[ "$#" -gt 0 ] || { echo "no series given" >&2; exit 2; }
: "${DEBSIGN_KEYID:?set DEBSIGN_KEYID to your Launchpad-registered GPG key}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$root/dist/ppa"
src="logscrub-$tag"
maint="Houssem Ben Ali <hbenali.tn@gmail.com>"

rm -rf "$out"
mkdir -p "$out"
cd "$out"

# Orig tarball: reproducible (sorted, fixed owner and mtime) so every series
# uploads byte-identical bytes.
git -C "$root" archive --prefix="$src/" "$tag" | tar -x
(cd "$src" && GOFLAGS=-mod=mod go mod vendor)
mtime="$(git -C "$root" log -1 --format=%ct "$tag")"
tar --sort=name --mtime="@$mtime" --owner=0 --group=0 --numeric-owner \
  -cf - "$src" | xz -9 > "logscrub_$tag.orig.tar.xz"

first=1
for series in "$@"; do
  rm -rf "$src"
  tar -xf "logscrub_$tag.orig.tar.xz"
  cp -r "$root/packaging/debian" "$src/debian"
  version="$tag-1~${series}1"
  cat > "$src/debian/changelog" <<CL
logscrub ($version) $series; urgency=medium

  * New upstream release $tag, see
    https://github.com/hbenali/logscrub/releases/tag/$tag

 -- $maint  $(date -R)
CL
  # -sa on the first upload sends the orig tarball, later series reuse it.
  include=-sd
  [ "$first" = 1 ] && include=-sa
  (cd "$src" && dpkg-buildpackage -S "$include" -d -us -uc)
  debsign -k "$DEBSIGN_KEYID" "logscrub_${version}_source.changes"
  first=0
done
rm -rf "$src"
ls -1 "$out"/*_source.changes

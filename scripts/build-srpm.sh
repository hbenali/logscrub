#!/usr/bin/env bash
# Builds the source RPM for Fedora Copr: the tag's sources plus the vendored Go
# modules (Copr builds have no network). Needs git, go and rpmbuild.
#
# Usage: scripts/build-srpm.sh TAG
# Output: dist/srpm/logscrub-TAG-1.src.rpm; upload with
#   copr-cli build hbenali/logscrub dist/srpm/logscrub-TAG-1.src.rpm
set -euo pipefail

tag="${1:?usage: build-srpm.sh TAG}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$root/dist/srpm"
src="logscrub-$tag"

rm -rf "$out"
mkdir -p "$out/SOURCES" "$out/SPECS"
cd "$out"

git -C "$root" archive --prefix="$src/" "$tag" | tar -x
mtime="$(git -C "$root" log -1 --format=%ct "$tag")"
tar_reproducibly() { tar --sort=name --mtime="@$mtime" --owner=0 --group=0 --numeric-owner "$@"; }
tar_reproducibly -cf - "$src" | gzip -n > "SOURCES/logscrub-$tag.tar.gz"
(cd "$src" && GOFLAGS=-mod=mod go mod vendor)
tar_reproducibly -cJf "SOURCES/logscrub-$tag-vendor.tar.xz" -C "$src" vendor
rm -rf "$src"

# The spec is taken from the working tree (older tags don't have one); only the
# version and the changelog entry follow the tag.
sed -e "s/^Version:.*/Version:        $tag/" \
    -e "/^%changelog/,\$d" "$root/packaging/rpm/logscrub.spec" > SPECS/logscrub.spec
cat >> SPECS/logscrub.spec <<CL
%changelog
* $(LC_ALL=C date '+%a %b %d %Y') Houssem Ben Ali <hbenali.tn@gmail.com> - $tag-1
- New upstream release $tag
CL

# no dist tag in the SRPM: every Copr chroot adds its own
rpmbuild -bs --define "_topdir $out" --define "dist %{nil}" SPECS/logscrub.spec
mv SRPMS/*.src.rpm .
ls -1 "$out"/*.src.rpm

#!/bin/sh
set -eu
version=${1:?usage: scripts/release.sh vX.Y.Z}
case "$version" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo 'expected version tag' >&2; exit 1;; esac
mkdir -p dist
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$stage/hnw" ./cmd/hnw
  cp LICENSE "$stage/LICENSE"
  cp docs/THIRD_PARTY_NOTICES.md "$stage/THIRD_PARTY_NOTICES.md"
  chmod 755 "$stage/hnw"
  chmod 644 "$stage/LICENSE" "$stage/THIRD_PARTY_NOTICES.md"
  tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -cf - -C "$stage" hnw LICENSE THIRD_PARTY_NOTICES.md | gzip -n > "dist/hnw_${version}_linux_${arch}.tar.gz"
done
(cd dist && sha256sum "hnw_${version}_linux_amd64.tar.gz" "hnw_${version}_linux_arm64.tar.gz" > SHA256SUMS)

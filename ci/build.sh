#!/usr/bin/env bash
# Cross-compile both commands for every supported platform into dist/.
# Usage: VERSION=1.2.3 ci/build.sh   (VERSION defaults to "dev")
set -euo pipefail

version="${VERSION:-dev}"
module="$(go list -m)"
targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"

rm -rf dist
mkdir -p dist
for target in $targets; do
  os="${target%/*}"
  arch="${target#*/}"
  extension=""
  if [ "$os" = "windows" ]; then
    extension=".exe"
  fi
  for command in google-claude-auth google-claude-verify-gateway; do
    output="dist/${command}_${version}_${os}_${arch}${extension}"
    echo "building $output"
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
      -ldflags "-s -w -X ${module}/internal/auth.Version=${version}" \
      -o "$output" "./cmd/${command}"
  done
done
(cd dist && sha256sum -- * > SHA256SUMS)

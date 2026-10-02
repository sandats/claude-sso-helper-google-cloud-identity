#!/usr/bin/env bash
# Print the next release version (without the "v" prefix).
# Reads `git ls-remote --tags --refs` output on stdin and bumps the patch of the
# highest vX.Y.Z tag; the first release is 0.1.0. Set RELEASE_VERSION (for example
# 0.2.0) to choose the version, such as for a minor or major bump.
set -euo pipefail

if [ -n "${RELEASE_VERSION:-}" ]; then
  version="${RELEASE_VERSION#v}"
  if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "RELEASE_VERSION must look like 1.2.3" >&2
    exit 1
  fi
  echo "$version"
  exit 0
fi

latest="$(sed -n 's#.*refs/tags/v\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)$#\1#p' |
  sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1)"
if [ -z "$latest" ]; then
  echo "0.1.0"
else
  IFS=. read -r major minor patch <<<"$latest"
  echo "$major.$minor.$((patch + 1))"
fi

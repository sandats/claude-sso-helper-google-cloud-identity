#!/usr/bin/env bash
# Build versioned binaries, publish them to the GitLab generic package registry and
# create a GitLab release for the current commit. Runs in GitLab CI on the default
# branch. Set DRY_RUN=1 to print the release request instead of sending anything.
set -euo pipefail

: "${CI_API_V4_URL:?}" "${CI_PROJECT_ID:?}" "${CI_COMMIT_SHA:?}" "${CI_JOB_TOKEN:?}"

tags="$(git ls-remote --tags --refs origin 'v*')"
if [ -z "${RELEASE_VERSION:-}" ] && grep -q "^${CI_COMMIT_SHA}[[:space:]]" <<<"$tags"; then
  echo "This commit already has a release tag; nothing to do."
  exit 0
fi
version="$("$(dirname "$0")/next-version.sh" <<<"$tags")"
echo "Releasing v${version}"

VERSION="$version" "$(dirname "$0")/build.sh"

package_url="${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/google-claude-auth/${version}"
links=""
for file in dist/*; do
  name="$(basename "$file")"
  if [ -z "${DRY_RUN:-}" ]; then
    curl --fail-with-body --silent --show-error --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
      --upload-file "$file" "${package_url}/${name}"
    echo
  fi
  links="${links:+${links},}{\"name\":\"${name}\",\"url\":\"${package_url}/${name}\",\"link_type\":\"package\"}"
done

description="Automated release of commit ${CI_COMMIT_SHA}. Verify downloads with SHA256SUMS."
payload="{\"name\":\"v${version}\",\"tag_name\":\"v${version}\",\"ref\":\"${CI_COMMIT_SHA}\",\"description\":\"${description}\",\"assets\":{\"links\":[${links}]}}"

if [ -n "${DRY_RUN:-}" ]; then
  echo "$payload"
  exit 0
fi
curl --fail-with-body --silent --show-error --request POST \
  --header "JOB-TOKEN: ${CI_JOB_TOKEN}" --header "Content-Type: application/json" \
  --data "$payload" "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/releases"
echo
echo "Created release v${version}"

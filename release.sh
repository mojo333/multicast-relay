#!/usr/bin/env bash
# Builds the Linux binaries and publishes them as a new GitHub release.
# Usage: ./release.sh vX.Y [notes-file]
# The notes file is added above the generated notes, for upgrade warnings.
set -euo pipefail

REPO="mojo333/multicast-relay"

die() { echo "release: $*" >&2; exit 1; }

TAG="${1:-}"
[[ ${TAG} =~ ^v[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || die "usage: ./release.sh vX.Y [notes-file]"

NOTES=()
if [[ -n ${2:-} ]]; then
  [[ -f $2 ]] || die "notes file $2 not found"
  # Made absolute because the script changes directory.
  NOTES=(--notes-file "$(cd "$(dirname "$2")" && pwd)/$(basename "$2")")
fi

cd "$(dirname "$0")"

# Release only what is on master, so that the tag matches the binaries.
[[ -z "$(git status --porcelain)" ]] || die "the checkout has uncommitted changes"
git fetch --quiet origin master
COMMIT="$(git rev-parse HEAD)"
[[ ${COMMIT} == "$(git rev-parse origin/master)" ]] || die "HEAD does not match origin/master"

# An existing release is never replaced.
EXISTING="$(git ls-remote --tags origin "refs/tags/${TAG}")"
[[ -z ${EXISTING} ]] || die "tag ${TAG} already exists"

BINDIR="$(mktemp -d)"
trap 'rm -rf "${BINDIR}"' EXIT

cd go
# Build with the Go version that go.mod names and CI tests.
GOTOOLCHAIN="go$(sed -n 's/^go //p' go.mod)"
export GOTOOLCHAIN

echo "==> Cross-compiling ${TAG} with ${GOTOOLCHAIN}..."
build() {
  CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.version=${TAG}" \
    -o "${BINDIR}/multicast-relay-$1" ./cmd/multicast-relay/
}
GOARCH=amd64 build amd64
GOARCH=arm64 build arm64
GOARCH=arm GOARM=7 build armv7
ls -lh "${BINDIR}"/multicast-relay-*

echo "==> Creating release ${TAG} at ${COMMIT}..."
gh release create "${TAG}" \
  --repo "${REPO}" \
  --target "${COMMIT}" \
  --title "${TAG}" \
  --generate-notes \
  ${NOTES[@]+"${NOTES[@]}"} \
  "${BINDIR}/multicast-relay-amd64" \
  "${BINDIR}/multicast-relay-arm64" \
  "${BINDIR}/multicast-relay-armv7"

echo "==> Done."
gh release view "${TAG}" --repo "${REPO}"

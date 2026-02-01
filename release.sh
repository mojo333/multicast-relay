#!/usr/bin/env bash
set -euo pipefail

REPO="mojo333/multicast-relay"
TAG="v2.1"
TARGET="master"
BINDIR="$(mktemp -d)"

echo "==> Deleting existing ${TAG} release and tag..."
gh release delete "${TAG}" --repo "${REPO}" --yes --cleanup-tag 2>/dev/null || true

echo "==> Cross-compiling binaries..."
cd "$(dirname "$0")/go"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64       go build -ldflags="-s -w" -o "${BINDIR}/multicast-relay-amd64" ./cmd/multicast-relay/
CGO_ENABLED=0 GOOS=linux GOARCH=arm64       go build -ldflags="-s -w" -o "${BINDIR}/multicast-relay-arm64" ./cmd/multicast-relay/
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o "${BINDIR}/multicast-relay-armv7" ./cmd/multicast-relay/

echo "==> Built binaries:"
ls -lh "${BINDIR}"/multicast-relay-*
file "${BINDIR}"/multicast-relay-*

echo "==> Creating ${TAG} release on ${TARGET}..."
gh release create "${TAG}" \
  --repo "${REPO}" \
  --target "${TARGET}" \
  --title "${TAG}" \
  --notes "$(cat <<'EOF'
## What's Changed since v2.0

### Code Quality
- Add doc comments to 15 undocumented functions across relay and main packages
- Clean up comments in main.go
- Rename Go module to `github.com/mojo333/multicast-relay`
- Update repository URL references

### Documentation
- Update README with information about the Go port
- Remove outdated netifaces installation instructions

### Housekeeping
- Delete stale committed binaries and build artifacts from the repo
- Remove Dockerfile (replaced by CI-built binaries)

## Binaries

Statically linked Linux binaries (no CGO, stripped):

- `multicast-relay-amd64` — Linux x86_64
- `multicast-relay-arm64` — Linux aarch64
- `multicast-relay-armv7` — Linux ARMv7 (e.g. Raspberry Pi)
EOF
)" \
  "${BINDIR}/multicast-relay-amd64" \
  "${BINDIR}/multicast-relay-arm64" \
  "${BINDIR}/multicast-relay-armv7"

echo "==> Cleaning up..."
rm -rf "${BINDIR}"

echo "==> Done. Release ${TAG} created."
gh release view "${TAG}" --repo "${REPO}"

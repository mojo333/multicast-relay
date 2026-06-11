#!/usr/bin/env bash
set -euo pipefail

REPO="mojo333/multicast-relay"
TAG="v2.7"
TARGET="master"
BINDIR="$(mktemp -d)"

echo "==> Deleting existing ${TAG} release and tag..."
gh release delete "${TAG}" --repo "${REPO}" --yes --cleanup-tag 2>/dev/null || true

echo "==> Cross-compiling binaries..."
cd "$(dirname "$0")/go"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64       go build -ldflags="-s -w -X main.version=${TAG}" -o "${BINDIR}/multicast-relay-amd64" ./cmd/multicast-relay/
CGO_ENABLED=0 GOOS=linux GOARCH=arm64       go build -ldflags="-s -w -X main.version=${TAG}" -o "${BINDIR}/multicast-relay-arm64" ./cmd/multicast-relay/
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-s -w -X main.version=${TAG}" -o "${BINDIR}/multicast-relay-armv7" ./cmd/multicast-relay/

echo "==> Built binaries:"
ls -lh "${BINDIR}"/multicast-relay-*
file "${BINDIR}"/multicast-relay-*

echo "==> Creating ${TAG} release on ${TARGET}..."
gh release create "${TAG}" \
  --repo "${REPO}" \
  --target "${TARGET}" \
  --title "${TAG}" \
  --notes "$(cat <<'EOF'
## What's Changed since v2.6

### Fixes
- Corrected `maxRemoteMessageLen` to match the worst-case AES-encrypted
  remote frame size (10276 bytes), preventing max-size packets from
  being rejected and dropping the remote connection.
- `EncryptFrame` now returns an error instead of silently truncating
  the wire-protocol length prefix if a frame body exceeds 65535 bytes.
- Fixed a goroutine leak in `dialRemote`: in-flight dial results are
  now discarded via a select against the relay's shutdown signal
  instead of blocking forever after `Close()`.

### Tests
- Added cipher tests for `EncryptFrame` round-trip/size limits and the
  Challenge/Respond/Verify handshake (coverage 59% -> 92.7%).
- Added relay regression tests for the frame size limit and dial
  shutdown path.

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

#!/usr/bin/env bash
set -euo pipefail

REPO="mojo333/multicast-relay"
TAG="v2.4"
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
## What's Changed since v2.3

### Code Quality
- `cipher.New()` now returns `(*Cipher, error)` instead of panicking on bad key input
- `syslogWriter.Write` correctly propagates errors instead of silently swallowing them
- `MdnsSetUnicastBit` avoids unnecessary allocation when the unicast bit is already set
- Extracted `createTransmitSocket` helper to eliminate duplicated socket setup code
- `remoteSockets()` caches connected-remote slice via `connsDirty` flag to avoid repeated allocations
- `readRemoteConnections` caps incoming message length to prevent oversized remote frames
- Decomposed `processPacket` into `applyMDNS`, `handleSSDP`, and `findReceivingIface` helpers
- Replaced `isENXIO` one-liner wrapper with direct `err == unix.ENXIO` comparison
- `ssdpSrc` state promoted to `PacketRelay` struct field (was a local variable)
- Loop receive buffer sized to `maxPacketSize`; `connectRemotes` guarded by `hasUnconnectedRemotes`
- Package-level `ipv4EtherType` var replaces per-instance struct field
- `fatal` closure in `main` replaces four duplicated validation-error-exit blocks

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

# multicast-relay

A Go reimplementation of Al Smith's Python multicast-relay. Relays broadcast and multicast UDP packets between network interfaces/VLANs to enable device discovery (Sonos, Chromecast, mDNS, SSDP) across network boundaries.

## Project Layout

```
go/
  cmd/multicast-relay/main.go       # CLI entry point, flag parsing, signal handling
  internal/relay/relay.go           # Core engine: PacketRelay, socket setup, Loop()
  internal/relay/packet.go          # IP/UDP checksums, packet modification, multicast/broadcast helpers
  internal/relay/arp.go             # ARP table lookup via /proc/net/arp
  internal/cipher/cipher.go         # AES-256-GCM encryption for remote relay connections
  internal/logger/logger.go         # slog-based logging (syslog, stdout, file, monitor)
  go.mod / go.sum
release.sh                          # Cross-compiles and publishes a GitHub release via gh
.github/workflows/build.yml         # CI: test + cross-compile for amd64/arm64/armv7
```

## Build & Test

All commands run from the `go/` directory:

```bash
cd go

# Run tests
go test ./... -v -count=1

# Vet
go vet ./...

# Build for host
go build ./cmd/multicast-relay/

# Cross-compile (as done in CI and release.sh)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64  go build -ldflags="-s -w" -o ../bin/multicast-relay-amd64 ./cmd/multicast-relay/
CGO_ENABLED=0 GOOS=linux GOARCH=arm64  go build -ldflags="-s -w" -o ../bin/multicast-relay-arm64 ./cmd/multicast-relay/
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o ../bin/multicast-relay-armv7 ./cmd/multicast-relay/
```

Releases are published with `./release.sh` (requires `gh` CLI).

## Key Architecture Notes

- **Raw sockets**: uses `AF_PACKET` sockets for packet capture and transmission (Linux only).
- **Event loop**: single-threaded, driven by `unix.Poll()` with a 1 s timeout in `relay.go:Loop()`.
- **Duplicate suppression**: ring buffer of 256 recent IP checksums prevents re-relaying the same packet.
- **Remote relay**: TCP transport with 2-byte length-prefixed framing; optional AES-256-GCM via `--aes`.
- **Interface recovery**: auto-recreates transmit sockets on `ENXIO` errors.
- **Buffer reuse**: `sync.Pool` for packet buffers.
- **Module**: `github.com/mojo333/multicast-relay`, Go 1.24, single external dependency `golang.org/x/sys`.

## Target Platforms

Linux only (uses `AF_PACKET`, `/proc/net/arp`, syslog). Primary deployment target is Unifi Dream Machine Pro (arm64).

## Default Relayed Traffic

| Protocol | Address | Port |
|----------|---------|------|
| mDNS | 224.0.0.251 | 5353 |
| SSDP | 239.255.255.250 | 1900 |
| Sonos discovery (broadcast) | — | 6969 |

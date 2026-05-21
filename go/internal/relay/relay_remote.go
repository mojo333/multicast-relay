package relay

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// remoteReadBuf tracks the read state for a single remote TCP connection.
// The protocol is length-prefixed: 2-byte big-endian length + payload.
type remoteReadBuf struct {
	buf        []byte
	offset     int
	msgLen     int       // -1 means we haven't read the length yet
	lastActive time.Time // updated on every successful read; used to detect stale partial messages
}

// readRemoteConnections does non-blocking reads from all remote TCP connections
// and processes any complete messages.
func (pr *PacketRelay) readRemoteConnections() {
	remotes := pr.remoteSockets()
	if len(remotes) == 0 {
		return
	}

	var failed []net.Conn
	for _, conn := range remotes {
		rb, ok := pr.remoteReadBufs[conn]
		if !ok {
			rb = &remoteReadBuf{buf: make([]byte, 0), msgLen: -1, lastActive: time.Now()}
			pr.remoteReadBufs[conn] = rb
		}

		// Set a short read deadline for non-blocking behavior
		conn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))

		tmp := make([]byte, 4096)
		for {
			n, err := conn.Read(tmp)
			if n > 0 {
				rb.buf = append(rb.buf, tmp[:n]...)
				rb.lastActive = time.Now()
			}
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					break // no more data available right now
				}
				// Real error — connection is dead
				pr.logger.Warning("REMOTE: Read error from %s: %s", conn.RemoteAddr(), err)
				failed = append(failed, conn)
				break
			}
			if n == 0 {
				break
			}
		}

		// Process complete messages from the buffer
		for {
			if rb.msgLen < 0 {
				if len(rb.buf) < 2 {
					break
				}
				rb.msgLen = int(binary.BigEndian.Uint16(rb.buf[:2]))
				rb.buf = rb.buf[2:]
				if rb.msgLen > maxRemoteMessageLen {
					pr.logger.Warning("REMOTE: Message too large (%d bytes) from %s — closing", rb.msgLen, conn.RemoteAddr())
					failed = append(failed, conn)
					break
				}
			}
			if len(rb.buf) < rb.msgLen {
				// Close connections that have been waiting on a partial message for too long.
				if time.Since(rb.lastActive) > 10*time.Second {
					pr.logger.Warning("REMOTE: Stale connection from %s (partial message timeout) — closing", conn.RemoteAddr())
					failed = append(failed, conn)
				}
				break
			}

			encrypted := rb.buf[:rb.msgLen]
			rb.buf = rb.buf[rb.msgLen:]
			rb.msgLen = -1

			decrypted, err := pr.aes.Decrypt(encrypted)
			if err != nil {
				// Close on any decryption failure — wrong key, tampered data, or replay.
				// No per-error detail logged to avoid timing side-channels.
				pr.logger.Warning("REMOTE: Decrypt error from %s — closing", conn.RemoteAddr())
				failed = append(failed, conn)
				break
			}

			// Validate magic bytes + sender IP + at least minimal packet
			if len(decrypted) < len(magicBytes)+4+minUDPPacketLen {
				pr.logger.Info("REMOTE: Packet too short from %s", conn.RemoteAddr())
				continue
			}
			if decrypted[0] != magicBytes[0] || decrypted[1] != magicBytes[1] ||
				decrypted[2] != magicBytes[2] || decrypted[3] != magicBytes[3] {
				pr.logger.Info("REMOTE: Invalid magic bytes from %s", conn.RemoteAddr())
				continue
			}

			senderAddr := AddrFrom4Bytes(decrypted[4:8]).String()
			packetData := decrypted[8:]

			pr.processPacket(packetData, senderAddr, "remote")
		}
	}

	for _, conn := range failed {
		delete(pr.remoteReadBufs, conn)
		pr.removeConnection(conn)
		conn.Close()
	}
}

// remoteSockets returns all active remote relay connections.
// It rebuilds the cached slice only when connsDirty is true.
func (pr *PacketRelay) remoteSockets() []net.Conn {
	if !pr.connsDirty {
		return pr.connectedRemotes
	}
	var conns []net.Conn
	conns = append(conns, pr.remoteConnections...)
	for _, ra := range pr.remoteAddrs {
		if ra.Conn != nil {
			conns = append(conns, ra.Conn)
		}
	}
	pr.connectedRemotes = conns
	pr.connsDirty = false
	return conns
}

// connectRemotes establishes TCP connections to configured remote relays.
func (pr *PacketRelay) connectRemotes() {
	for _, remote := range pr.remoteAddrs {
		if remote.Conn != nil {
			continue
		}
		if !remote.ConnectFailure.IsZero() && time.Since(remote.ConnectFailure) < time.Duration(pr.remoteRetry)*time.Second {
			continue
		}
		pr.logger.Info("REMOTE: Connecting to remote %s", remote.Addr)
		remote.Connecting = true
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", remote.Addr, pr.remotePort), 5*time.Second)
		if err != nil {
			remote.Connecting = false
			remote.ConnectFailure = time.Now()
			pr.logger.Warning("REMOTE: Failed to connect to %s: %s", remote.Addr, err)
			continue
		}

		// Client-side HMAC challenge-response: read server nonce, send HMAC-SHA256 response.
		if pr.aes.Enabled() {
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			challenge := make([]byte, 16)
			if _, err := io.ReadFull(conn, challenge); err != nil {
				remote.Connecting = false
				remote.ConnectFailure = time.Now()
				conn.Close()
				pr.logger.Warning("REMOTE: Auth challenge read from %s failed: %s", remote.Addr, err)
				continue
			}
			response := pr.aes.Respond(challenge)
			if _, err := conn.Write(response); err != nil {
				remote.Connecting = false
				remote.ConnectFailure = time.Now()
				conn.Close()
				pr.logger.Warning("REMOTE: Auth response send to %s failed: %s", remote.Addr, err)
				continue
			}
			conn.SetDeadline(time.Time{})
		}

		remote.Conn = conn
		remote.Connecting = false
		pr.connsDirty = true
		pr.logger.Info("REMOTE: Connection to %s established", remote.Addr)
	}
}

// removeConnection removes a remote connection from the active set and cleans up its read buffer.
func (pr *PacketRelay) removeConnection(conn net.Conn) {
	delete(pr.remoteReadBufs, conn)
	pr.connsDirty = true
	for i, c := range pr.remoteConnections {
		if c == conn {
			pr.remoteConnections = append(pr.remoteConnections[:i], pr.remoteConnections[i+1:]...)
			return
		}
	}
	for _, ra := range pr.remoteAddrs {
		if ra.Conn == conn {
			ra.Conn = nil
			ra.Connecting = false
			ra.ConnectFailure = time.Now()
		}
	}
}

// acceptLoop runs in a dedicated goroutine, accepting TCP connections and sending
// validated ones to acceptCh for the main loop to consume.
func (pr *PacketRelay) acceptLoop() {
	allowedSet := make(map[string]bool, len(pr.listenAddr))
	for _, addr := range pr.listenAddr {
		allowedSet[addr] = true
	}

	for {
		conn, err := pr.listener.Accept()
		if err != nil {
			// Listener was closed; exit goroutine.
			return
		}

		tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			conn.Close()
			continue
		}

		remoteIP := tcpAddr.IP.String()
		if !allowedSet[remoteIP] {
			pr.logger.Warning("Refusing connection from %s - not in allowed list", remoteIP)
			conn.Close()
			continue
		}

		// HMAC challenge-response: send 16-byte nonce, expect HMAC-SHA256 response.
		// Only active when encryption (and therefore a shared key) is configured.
		if pr.aes.Enabled() {
			challenge, err := pr.aes.Challenge()
			if err != nil {
				pr.logger.Warning("REMOTE: Challenge generation failed: %s", err)
				conn.Close()
				continue
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write(challenge); err != nil {
				conn.Close()
				continue
			}
			response := make([]byte, 32)
			if _, err := io.ReadFull(conn, response); err != nil {
				pr.logger.Warning("REMOTE: Auth handshake failed from %s", remoteIP)
				conn.Close()
				continue
			}
			conn.SetDeadline(time.Time{})
			if !pr.aes.Verify(challenge, response) {
				pr.logger.Warning("REMOTE: Auth rejected from %s — wrong key", remoteIP)
				conn.Close()
				continue
			}
		}

		pr.acceptCh <- conn
	}
}

// hasUnconnectedRemotes returns true if any remote relay target has no active connection.
func (pr *PacketRelay) hasUnconnectedRemotes() bool {
	for _, ra := range pr.remoteAddrs {
		if ra.Conn == nil {
			return true
		}
	}
	return false
}

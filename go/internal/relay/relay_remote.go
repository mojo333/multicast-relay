package relay

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// remoteReadBuf is defined in relay_types.go.

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
			rb = &remoteReadBuf{msgLen: -1, lastActive: time.Now()}
			pr.remoteReadBufs[conn] = rb
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))

		for {
			n, err := conn.Read(pr.remoteTmpBuf)
			if n > 0 {
				rb.buf.Write(pr.remoteTmpBuf[:n])
				rb.lastActive = time.Now()
			}
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					break
				}
				pr.logger.Warning("REMOTE: Read error from %s: %s", conn.RemoteAddr(), err)
				failed = append(failed, conn)
				break
			}
			if n == 0 {
				break
			}
		}

		// Process complete messages from the buffer.
		for {
			if rb.msgLen < 0 {
				if rb.buf.Len() < 2 {
					break
				}
				rb.msgLen = int(binary.BigEndian.Uint16(rb.buf.Bytes()[:2]))
				rb.buf.Next(2)
				if rb.msgLen > maxRemoteMessageLen {
					pr.logger.Warning("REMOTE: Message too large (%d bytes) from %s — closing", rb.msgLen, conn.RemoteAddr())
					failed = append(failed, conn)
					break
				}
			}
			if rb.buf.Len() < rb.msgLen {
				if time.Since(rb.lastActive) > 10*time.Second {
					pr.logger.Warning("REMOTE: Stale connection from %s (partial message timeout) — closing", conn.RemoteAddr())
					failed = append(failed, conn)
				}
				break
			}

			encrypted := rb.buf.Next(rb.msgLen)
			rb.msgLen = -1

			decrypted, err := pr.aes.Decrypt(encrypted)
			if err != nil {
				pr.logger.Warning("REMOTE: Decrypt error from %s — closing", conn.RemoteAddr())
				failed = append(failed, conn)
				break
			}

			if len(decrypted) < len(magicBytes)+4+minUDPPacketLen {
				pr.logger.Info("REMOTE: Packet too short from %s", conn.RemoteAddr())
				continue
			}
			if decrypted[0] != magicBytes[0] || decrypted[1] != magicBytes[1] ||
				decrypted[2] != magicBytes[2] || decrypted[3] != magicBytes[3] {
				pr.logger.Info("REMOTE: Invalid magic bytes from %s", conn.RemoteAddr())
				continue
			}

			senderAddr := AddrFrom4Bytes(decrypted[4:8])
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

// connectRemotes kicks off non-blocking dials for any unconnected remote relay.
// Each dial runs in its own goroutine; results arrive on pr.connectResultCh.
func (pr *PacketRelay) connectRemotes() {
	for _, remote := range pr.remoteAddrs {
		if remote.Conn != nil || remote.Connecting {
			continue
		}
		if !remote.ConnectFailure.IsZero() && time.Since(remote.ConnectFailure) < time.Duration(pr.remoteRetry)*time.Second {
			continue
		}
		remote.Connecting = true
		pr.logger.Info("REMOTE: Connecting to remote %s", remote.Addr)
		go pr.dialRemote(remote)
	}
}

// dialRemote dials a remote relay (including auth handshake) and sends the result to connectResultCh.
// Runs in its own goroutine so it does not block the main loop.
func (pr *PacketRelay) dialRemote(ra *RemoteAddr) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ra.Addr, pr.remotePort), 5*time.Second)
	if err != nil {
		pr.connectResultCh <- connectResult{ra: ra, err: err}
		return
	}

	if pr.aes.Enabled() {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		challenge := make([]byte, 16)
		if _, err := io.ReadFull(conn, challenge); err != nil {
			conn.Close()
			pr.connectResultCh <- connectResult{ra: ra, err: fmt.Errorf("auth challenge: %w", err)}
			return
		}
		response := pr.aes.Respond(challenge)
		if _, err := conn.Write(response); err != nil {
			conn.Close()
			pr.connectResultCh <- connectResult{ra: ra, err: fmt.Errorf("auth response: %w", err)}
			return
		}
		conn.SetDeadline(time.Time{})
	}

	pr.connectResultCh <- connectResult{ra: ra, conn: conn}
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

// hasUnconnectedRemotes returns true if any remote is disconnected, not actively dialing,
// and past its retry backoff window.
func (pr *PacketRelay) hasUnconnectedRemotes() bool {
	for _, ra := range pr.remoteAddrs {
		if ra.Conn == nil && !ra.Connecting {
			if ra.ConnectFailure.IsZero() || time.Since(ra.ConnectFailure) >= time.Duration(pr.remoteRetry)*time.Second {
				return true
			}
		}
	}
	return false
}

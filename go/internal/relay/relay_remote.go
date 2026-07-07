package relay

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// startReader launches the per-connection reader goroutine. Reading in a
// dedicated goroutine keeps blocking reads off the single-threaded event loop:
// a slow or idle remote peer can never stall local relaying.
func (pr *PacketRelay) startReader(conn net.Conn) {
	go pr.runReader(conn)
}

// runReader reads length-prefixed frames from a single remote connection,
// decrypts and validates them, and delivers decoded packets to the main loop via
// remotePacketCh. On any fatal error it reports the connection on remoteFailedCh
// and exits. It owns all per-connection read state, so no locking is needed.
func (pr *PacketRelay) runReader(conn net.Conn) {
	var buf []byte
	msgLen := -1
	var lastSeq uint64
	var seqSet bool
	tmp := make([]byte, 4096)

	fail := func() {
		select {
		case pr.remoteFailedCh <- conn:
		case <-pr.done:
		}
	}

	for {
		select {
		case <-pr.done:
			return
		default:
		}

		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			for {
				if msgLen < 0 {
					if len(buf) < 2 {
						break
					}
					msgLen = int(binary.BigEndian.Uint16(buf[:2]))
					buf = buf[2:]
					if msgLen > maxRemoteMessageLen {
						pr.logger.Warning("REMOTE: Message too large (%d bytes) from %s — closing", msgLen, conn.RemoteAddr())
						fail()
						return
					}
				}
				if len(buf) < msgLen {
					break
				}
				encrypted := buf[:msgLen]
				buf = buf[msgLen:]
				msgLen = -1

				if !pr.deliverRemoteFrame(conn, encrypted, &lastSeq, &seqSet) {
					fail()
					return
				}
			}
			// Reclaim the consumed prefix so buf does not grow unbounded.
			if len(buf) == 0 {
				buf = buf[:0]
			}
		}
		if err != nil {
			fail()
			return
		}
	}
}

// deliverRemoteFrame decrypts and validates a single frame and, if valid, sends
// the decoded packet to the main loop. It returns false only on a fatal error
// that should close the connection (decrypt failure); malformed-but-nonfatal
// frames are logged and skipped (returning true).
func (pr *PacketRelay) deliverRemoteFrame(conn net.Conn, encrypted []byte, lastSeq *uint64, seqSet *bool) bool {
	decrypted, err := pr.aes.Decrypt(encrypted)
	if err != nil {
		pr.logger.Warning("REMOTE: Decrypt error from %s — closing", conn.RemoteAddr())
		return false
	}

	if len(decrypted) < remoteHeaderLen+minUDPPacketLen {
		pr.logger.Info("REMOTE: Packet too short from %s", conn.RemoteAddr())
		return true
	}
	// Frame plaintext: seq(8) || magic(4) || senderIP(4) || packet.
	seq := binary.BigEndian.Uint64(decrypted[0:8])
	if decrypted[8] != magicBytes[0] || decrypted[9] != magicBytes[1] ||
		decrypted[10] != magicBytes[2] || decrypted[11] != magicBytes[3] {
		pr.logger.Info("REMOTE: Invalid magic bytes from %s", conn.RemoteAddr())
		return true
	}
	// Replay protection: reject frames whose sequence number does not advance.
	// Gaps are allowed (a frame may be dropped by a full write queue), but a
	// repeated or older sequence is a replay.
	if *seqSet && seq <= *lastSeq {
		pr.logger.Info("REMOTE: Dropping replayed frame (seq %d <= %d) from %s", seq, *lastSeq, conn.RemoteAddr())
		return true
	}
	*lastSeq = seq
	*seqSet = true

	senderAddr := AddrFrom4Bytes(decrypted[12:16])
	// Copy the packet: decrypted may alias reused read state, and processPacket
	// (which runs later on the main loop) mutates the buffer in place.
	pkt := make([]byte, len(decrypted)-16)
	copy(pkt, decrypted[16:])

	select {
	case pr.remotePacketCh <- remotePacket{senderAddr: senderAddr, data: pkt}:
	case <-pr.done:
	}
	return true
}

// drainRemotePackets processes packets decoded by reader goroutines and cleans up
// failed connections. Called from the main loop.
func (pr *PacketRelay) drainRemotePackets() {
	for {
		select {
		case rp := <-pr.remotePacketCh:
			pr.processPacket(rp.data, rp.senderAddr, "remote")
		case conn := <-pr.remoteFailedCh:
			pr.removeConnection(conn)
			conn.Close()
		default:
			return
		}
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
		pr.sendConnectResult(connectResult{ra: ra, err: err})
		return
	}

	if pr.aes.Enabled() {
		conn.SetDeadline(time.Now().Add(5 * time.Second))

		// 1. Answer the server's challenge to prove we know the key.
		serverChallenge := make([]byte, 16)
		if _, err := io.ReadFull(conn, serverChallenge); err != nil {
			conn.Close()
			pr.sendConnectResult(connectResult{ra: ra, err: fmt.Errorf("auth challenge: %w", err)})
			return
		}
		if _, err := conn.Write(pr.aes.Respond(serverChallenge)); err != nil {
			conn.Close()
			pr.sendConnectResult(connectResult{ra: ra, err: fmt.Errorf("auth response: %w", err)})
			return
		}

		// 2. Challenge the server in return and verify it knows the key, so we
		// never relay to an impostor endpoint (mutual authentication).
		clientChallenge, err := pr.aes.Challenge()
		if err != nil {
			conn.Close()
			pr.sendConnectResult(connectResult{ra: ra, err: fmt.Errorf("auth challenge gen: %w", err)})
			return
		}
		if _, err := conn.Write(clientChallenge); err != nil {
			conn.Close()
			pr.sendConnectResult(connectResult{ra: ra, err: fmt.Errorf("auth challenge send: %w", err)})
			return
		}
		serverResponse := make([]byte, 32)
		if _, err := io.ReadFull(conn, serverResponse); err != nil {
			conn.Close()
			pr.sendConnectResult(connectResult{ra: ra, err: fmt.Errorf("server auth read: %w", err)})
			return
		}
		if !pr.aes.Verify(clientChallenge, serverResponse) {
			conn.Close()
			pr.sendConnectResult(connectResult{ra: ra, err: fmt.Errorf("server authentication failed — wrong key")})
			return
		}
		conn.SetDeadline(time.Time{})
	}

	pr.sendConnectResult(connectResult{ra: ra, conn: conn})
}

// sendConnectResult delivers a dial outcome to the main loop. If the relay has
// been closed, nothing drains connectResultCh anymore, so it discards the
// result instead — otherwise the dial goroutine would block forever.
func (pr *PacketRelay) sendConnectResult(res connectResult) {
	select {
	case pr.connectResultCh <- res:
	case <-pr.done:
		if res.conn != nil {
			res.conn.Close()
		}
	}
}

// removeConnection removes a remote connection from the active set and stops its
// writer goroutine. The reader goroutine exits on its own once the connection is
// closed by the caller.
func (pr *PacketRelay) removeConnection(conn net.Conn) {
	pr.stopWriter(conn)
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

		// Mutual HMAC challenge-response authentication (only when a shared key is
		// configured). The server proves the client knows the key AND proves its
		// own knowledge of the key to the client, so neither side trusts an
		// unauthenticated peer.
		if pr.aes.Enabled() {
			conn.SetDeadline(time.Now().Add(5 * time.Second))

			// 1. Challenge the client and verify its response.
			serverChallenge, err := pr.aes.Challenge()
			if err != nil {
				pr.logger.Warning("REMOTE: Challenge generation failed: %s", err)
				conn.Close()
				continue
			}
			if _, err := conn.Write(serverChallenge); err != nil {
				conn.Close()
				continue
			}
			clientResponse := make([]byte, 32)
			if _, err := io.ReadFull(conn, clientResponse); err != nil {
				pr.logger.Warning("REMOTE: Auth handshake failed from %s", remoteIP)
				conn.Close()
				continue
			}
			if !pr.aes.Verify(serverChallenge, clientResponse) {
				pr.logger.Warning("REMOTE: Auth rejected from %s — wrong key", remoteIP)
				conn.Close()
				continue
			}

			// 2. Answer the client's challenge to prove our identity.
			clientChallenge := make([]byte, 16)
			if _, err := io.ReadFull(conn, clientChallenge); err != nil {
				pr.logger.Warning("REMOTE: Auth handshake failed from %s", remoteIP)
				conn.Close()
				continue
			}
			if _, err := conn.Write(pr.aes.Respond(clientChallenge)); err != nil {
				conn.Close()
				continue
			}
			conn.SetDeadline(time.Time{})
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

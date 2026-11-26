package relay

import (
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// Loop runs the main packet relay event loop.
// It closes the relay's sockets and connections when it returns.
func (pr *PacketRelay) Loop() error {
	defer pr.cleanUp()
	buf := make([]byte, maxPacketSize)
	nextIfaceCheck := time.Now().Add(ifaceCheckInterval)

	// When remote relay is active, remote TCP connections are serviced once per
	// loop iteration, so a shorter poll timeout bounds remote packet latency when
	// the box is otherwise idle. Poll still wakes immediately on local traffic.
	pollTimeoutMs := 1000
	if len(pr.remoteAddrs) > 0 || len(pr.listenAddr) > 0 {
		pollTimeoutMs = 100
	}

	for {
		select {
		case <-pr.done:
			return nil
		default:
		}

		if !time.Now().Before(nextIfaceCheck) {
			if err := pr.reopenChangedInterfaces(); err != nil {
				return err
			}
			nextIfaceCheck = time.Now().Add(ifaceCheckInterval)
		}

		if pr.hasUnconnectedRemotes() {
			pr.connectRemotes()
		}

		if pr.pollDirty {
			pr.rebuildPollFds()
		}

		if len(pr.pollFds) == 0 {
			time.Sleep(time.Second)
			continue
		}

		// Drain async dial results (non-blocking).
		if pr.connectResultCh != nil {
		drainConnect:
			for {
				select {
				case result := <-pr.connectResultCh:
					result.ra.Connecting = false
					if result.err != nil {
						result.ra.ConnectFailure = time.Now()
						pr.logger.Warning("REMOTE: Failed to connect to %s: %s", result.ra.Addr, result.err)
					} else {
						result.ra.Conn = result.conn
						pr.connsDirty = true
						pr.startReader(result.conn)
						pr.logger.Info("REMOTE: Connection to %s established", result.ra.Addr)
					}
				default:
					break drainConnect
				}
			}
		}

		// Drain accepted connections (non-blocking).
		if pr.acceptCh != nil {
		drainAccept:
			for {
				select {
				case conn := <-pr.acceptCh:
					pr.remoteConnections = append(pr.remoteConnections, conn)
					pr.connsDirty = true
					pr.startReader(conn)
					pr.logger.Info("REMOTE: Accepted connection from %s", conn.RemoteAddr())
				default:
					break drainAccept
				}
			}
		}

		// Process packets decoded by remote reader goroutines.
		pr.drainRemotePackets()

		// Clear revents before polling
		for i := range pr.pollFds {
			pr.pollFds[i].Revents = 0
		}

		n, err := unix.Poll(pr.pollFds, pollTimeoutMs)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("poll error: %w", err)
		}
		if n == 0 {
			continue
		}

		for i, pfd := range pr.pollFds { // pollFds[i] belongs to receivers[i]
			if pfd.Revents&unix.POLLIN == 0 {
				continue
			}

			rx := pr.receivers[i]

			// Local receiver. processPacket runs synchronously and copies whatever
			// it needs to retain, so buf can be passed directly without a defensive
			// copy into a pooled buffer.
			nread, from, err := unix.Recvfrom(int(pfd.Fd), buf, 0)
			if err != nil {
				pr.logger.Warning("Error receiving packet: %s", err)
				continue
			}
			if nread < minUDPPacketLen {
				continue
			}

			sa, ok := from.(*unix.SockaddrInet4)
			if !ok {
				continue
			}
			senderAddr := AddrFrom4Bytes(sa.Addr[:])
			packet := buf[:nread]
			ipHeaderLength := int(packet[0]&0x0f) * 4
			if ipHeaderLength+4 > nread || int(binary.BigEndian.Uint16(packet[ipHeaderLength+2:])) != rx.port {
				continue
			}
			if total := int(binary.BigEndian.Uint16(packet[2:4])); total > nread {
				pr.logger.Warning("Dropping truncated datagram from %s: %d bytes, at most %d are supported", senderAddr, total, len(buf))
				continue
			}
			if rx.readdressAs.IsValid() {
				addr := rx.readdressAs.As4()
				copy(packet[16:20], addr[:])
				ComputeIPChecksum(packet, ipHeaderLength)
			}
			// With one interface on two networks the sender's address has to say
			// which side the packet came from.
			arrival := rx.iface
			if arrival == "" || pr.oneInterface {
				arrival = "local"
			}
			pr.processPacket(packet, senderAddr, arrival, nil)
		}
	}
}

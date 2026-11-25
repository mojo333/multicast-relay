package relay

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// Loop runs the main packet relay event loop.
func (pr *PacketRelay) Loop() error {
	buf := make([]byte, maxPacketSize)

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

		for _, pfd := range pr.pollFds {
			if pfd.Revents&unix.POLLIN == 0 {
				continue
			}

			// Local receiver. processPacket runs synchronously and copies whatever
			// it needs to retain, so buf can be passed directly without a defensive
			// copy into a pooled buffer.
			nread, from, err := unix.Recvfrom(int(pfd.Fd), buf, 0)
			if err != nil {
				pr.logger.Warning("Error receiving packet: %s", err)
				continue
			}
			if nread == 0 {
				continue
			}

			sa, ok := from.(*unix.SockaddrInet4)
			if !ok {
				continue
			}
			senderAddr := AddrFrom4Bytes(sa.Addr[:])
			pr.processPacket(buf[:nread], senderAddr, "local")
		}
	}
}

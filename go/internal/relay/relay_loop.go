package relay

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// Loop runs the main packet relay event loop.
func (pr *PacketRelay) Loop() error {
	buf := make([]byte, maxPacketSize)

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

		// Drain accepted connections (non-blocking)
		if pr.acceptCh != nil {
		drainAccept:
			for {
				select {
				case conn := <-pr.acceptCh:
					pr.remoteConnections = append(pr.remoteConnections, conn)
					pr.connsDirty = true
					pr.logger.Info("REMOTE: Accepted connection from %s", conn.RemoteAddr())
				default:
					break drainAccept
				}
			}
		}

		// Read from remote TCP connections
		pr.readRemoteConnections()

		// Clear revents before polling
		for i := range pr.pollFds {
			pr.pollFds[i].Revents = 0
		}

		n, err := unix.Poll(pr.pollFds, 1000) // 1 second timeout
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

			// Local receiver
			nread, from, err := unix.Recvfrom(int(pfd.Fd), buf, 0)
			if err != nil {
				pr.logger.Warning("Error receiving packet: %s", err)
				continue
			}
			if nread == 0 {
				continue
			}

			dataBp := getBuffer(nread)
			copy(*dataBp, buf[:nread])

			sa, ok := from.(*unix.SockaddrInet4)
			if !ok {
				putBuffer(dataBp)
				continue
			}
			senderAddr := AddrFrom4Bytes(sa.Addr[:]).String()

			pr.processPacket(*dataBp, senderAddr, "local")
			putBuffer(dataBp)
		}
	}
}

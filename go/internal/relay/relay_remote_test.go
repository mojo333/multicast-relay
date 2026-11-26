package relay

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mojo333/multicast-relay/internal/logger"
)

func TestBouncedRemotePacketIsDroppedWhenTTLRewrites(t *testing.T) {
	pr := newReaderTestRelay(t)
	defer close(pr.done)
	pr.ttl = 4
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	pr.connectedRemotes = []net.Conn{local}
	addRule(pr, SSDPMcastAddr, SSDPMcastPort)

	packet := minUDPTestPacket("192.168.1.100", "239.255.255.250", 1234, 1900)
	ComputeIPChecksum(packet, 20)
	bounced := append([]byte(nil), packet...) // processPacket rewrites the TTL in place
	sender := netip.MustParseAddr("192.168.1.100")

	pr.processPacket(packet, sender, "local", nil)
	pr.processPacket(bounced, sender, "remote", nil)

	if pr.remoteSeq != 1 {
		t.Errorf("packet forwarded to remotes %d times, want 1", pr.remoteSeq)
	}
}

func newFileLogRelay(t *testing.T) (*PacketRelay, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "relay.log")
	log, err := logger.New(false, path, false)
	if err != nil {
		t.Fatal(err)
	}
	pr := newReaderTestRelay(t)
	pr.logger = log
	return pr, path
}

func waitForLog(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		b, _ := os.ReadFile(path)
		if strings.Contains(string(b), want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("log does not contain %q: %q", want, b)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRemoteReadErrorIsLogged(t *testing.T) {
	pr, path := newFileLogRelay(t)
	defer close(pr.done)
	server, client := net.Pipe()
	defer server.Close()

	pr.startReader(server)
	client.Close()

	waitForLog(t, path, "REMOTE: Read error")
}

func TestRemoteWriteErrorIsLogged(t *testing.T) {
	pr, path := newFileLogRelay(t)
	defer close(pr.done)
	server, client := net.Pipe()
	defer server.Close()
	client.Close()

	pr.queueRemoteFrame(server, []byte("frame"))

	waitForLog(t, path, "REMOTE: Write error")
}

// connectPair runs a real handshake and returns both ends of the connection.
func connectPair(t *testing.T, server, client *PacketRelay) (serverConn, clientConn net.Conn) {
	t.Helper()
	go client.dialRemote(client.remoteAddrs[0])
	select {
	case serverConn = <-server.acceptCh:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not accept")
	}
	select {
	case res := <-client.connectResultCh:
		if res.err != nil {
			t.Fatalf("client handshake failed: %v", res.err)
		}
		clientConn = res.conn
	case <-time.After(3 * time.Second):
		t.Fatal("client dial produced no result")
	}
	t.Cleanup(func() { serverConn.Close(); clientConn.Close() })
	return serverConn, clientConn
}

// captureFrame relays one packet from the client and returns the raw wire bytes.
func captureFrame(t *testing.T, client *PacketRelay, clientConn, serverConn net.Conn) []byte {
	t.Helper()
	client.connectedRemotes, client.connsDirty = []net.Conn{clientConn}, false
	packet := minUDPTestPacket("192.168.1.100", "239.255.255.250", 1234, 1900)
	client.recent = [maxRecentPackets]seenPacket{} // allow the same packet again
	client.processPacket(packet, netip.MustParseAddr("192.168.1.100"), "local", nil)

	serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer serverConn.SetReadDeadline(time.Time{})
	frame := make([]byte, 2)
	if _, err := io.ReadFull(serverConn, frame); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(frame))
	if _, err := io.ReadFull(serverConn, body); err != nil {
		t.Fatal(err)
	}
	return append(frame, body...)
}

func expectRejected(t *testing.T, pr *PacketRelay, conn net.Conn) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-pr.remotePacketCh:
			t.Fatal("frame from another connection or direction was accepted")
		case got := <-pr.remoteFailedCh:
			if got == conn { // earlier subtests' connections also report here
				return
			}
		case <-deadline:
			t.Fatal("frame was neither accepted nor rejected")
		}
	}
}

func TestRemoteFramesAreBoundToOneConnectionAndDirection(t *testing.T) {
	port := freeTCPPort(t)
	newRelay := func(listen, remote []string) *PacketRelay {
		pr, err := New(Config{
			Listen: listen, Remote: remote, RemotePort: port,
			AESKey: "shared-secret", Logger: newTestLogger(t),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pr.Close)
		addRule(pr, SSDPMcastAddr, SSDPMcastPort)
		return pr
	}
	server := newRelay([]string{"127.0.0.1"}, nil)
	client := newRelay(nil, []string{"127.0.0.1"})

	server1, client1 := connectPair(t, server, client)
	captured := captureFrame(t, client, client1, server1)

	t.Run("genuine frame is accepted on its own connection", func(t *testing.T) {
		s, c := connectPair(t, server, client)
		server.startReader(s)
		client.connectedRemotes, client.connsDirty = []net.Conn{c}, false
		client.recent = [maxRecentPackets]seenPacket{}
		client.processPacket(minUDPTestPacket("192.168.1.100", "239.255.255.250", 1234, 1900),
			netip.MustParseAddr("192.168.1.100"), "local", nil)
		select {
		case <-server.remotePacketCh:
		case <-time.After(2 * time.Second):
			t.Fatal("genuine frame was not delivered")
		}
	})

	t.Run("replay on a new connection is rejected", func(t *testing.T) {
		s, c := connectPair(t, server, client)
		server.startReader(s)
		if _, err := c.Write(captured); err != nil {
			t.Fatal(err)
		}
		expectRejected(t, server, s)
	})

	t.Run("frame reflected to its sender is rejected", func(t *testing.T) {
		client.startReader(client1)
		if _, err := server1.Write(captured); err != nil {
			t.Fatal(err)
		}
		expectRejected(t, client, client1)
	})
}

package relay

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mojo333/multicast-relay/internal/cipher"
	"github.com/mojo333/multicast-relay/internal/logger"
)

func TestIsDuplicate(t *testing.T) {
	pr := &PacketRelay{}

	// Empty ring - nothing is duplicate
	if pr.isDuplicate(0x1234) {
		t.Error("expected 0x1234 to not be duplicate in empty ring")
	}

	pr.addChecksum(0x1234)

	if !pr.isDuplicate(0x1234) {
		t.Error("expected 0x1234 to be duplicate after adding")
	}

	// Different value should not be duplicate
	if pr.isDuplicate(0x5678) {
		t.Error("expected 0x5678 to not be duplicate")
	}
}

func TestAddChecksumMultiple(t *testing.T) {
	pr := &PacketRelay{}

	pr.addChecksum(0x0001)
	pr.addChecksum(0x0002)
	pr.addChecksum(0x0003)

	if !pr.isDuplicate(0x0001) {
		t.Error("expected 0x0001 to be duplicate")
	}
	if !pr.isDuplicate(0x0002) {
		t.Error("expected 0x0002 to be duplicate")
	}
	if !pr.isDuplicate(0x0003) {
		t.Error("expected 0x0003 to be duplicate")
	}
	if pr.isDuplicate(0x0004) {
		t.Error("expected 0x0004 to not be duplicate")
	}
}

func TestDuplicateRingBufferWrap(t *testing.T) {
	pr := &PacketRelay{}

	// Fill the ring buffer completely with values 0..255
	for i := 0; i < maxRecentChecksums; i++ {
		pr.addChecksum(uint16(i))
	}

	// All values 0..255 should be present
	for i := 0; i < maxRecentChecksums; i++ {
		if !pr.isDuplicate(uint16(i)) {
			t.Errorf("expected %d to be duplicate before wrap", i)
		}
	}

	// Add one more value, overwriting index 0 (which held value 0)
	pr.addChecksum(0xFFFF)

	// 0xFFFF should be found
	if !pr.isDuplicate(0xFFFF) {
		t.Error("expected 0xFFFF to be duplicate after adding")
	}

	// Value 0 was at index 0, now overwritten by 0xFFFF
	if pr.isDuplicate(0) {
		t.Error("expected 0 to no longer be duplicate after ring wrap")
	}

	// Values 1..255 should still be present
	for i := 1; i < maxRecentChecksums; i++ {
		if !pr.isDuplicate(uint16(i)) {
			t.Errorf("expected %d to still be duplicate after wrap", i)
		}
	}
}

func TestDuplicateRingBufferOverflow(t *testing.T) {
	pr := &PacketRelay{}

	// Add 2x the ring size to fully cycle through
	for i := 0; i < maxRecentChecksums*2; i++ {
		pr.addChecksum(uint16(i))
	}

	// Only the last maxRecentChecksums values should be present (256..511)
	for i := 0; i < maxRecentChecksums; i++ {
		if pr.isDuplicate(uint16(i)) {
			t.Errorf("expected %d to be evicted after full cycle", i)
		}
	}
	for i := maxRecentChecksums; i < maxRecentChecksums*2; i++ {
		if !pr.isDuplicate(uint16(i)) {
			t.Errorf("expected %d to be present", i)
		}
	}
}

func TestDuplicateDetectionSequentialStress(t *testing.T) {
	// The ring buffer is intentionally not safe for concurrent use.
	// It is only accessed from the single-threaded main loop.
	// This test validates correctness under heavy sequential use.
	pr := &PacketRelay{}

	for g := 0; g < 10; g++ {
		base := uint16(g) * 100
		for i := uint16(0); i < 100; i++ {
			pr.addChecksum(base + i)
			if !pr.isDuplicate(base + i) {
				t.Errorf("expected %d to be duplicate after adding", base+i)
			}
		}
	}
}

// --- Interface filter tests ---

func TestIsAllowedByFilterNoFilters(t *testing.T) {
	pr := &PacketRelay{}
	// With no filters, everything should be allowed
	if !pr.isAllowedByFilter(netip.MustParseAddr("192.168.1.100"), "eth0") {
		t.Error("expected allowed with no filters")
	}
	if !pr.isAllowedByFilter(netip.MustParseAddr("10.0.0.1"), "wlan0") {
		t.Error("expected allowed with no filters")
	}
}

func TestIsAllowedByFilter(t *testing.T) {
	pr := &PacketRelay{
		parsedFilters: []parsedFilter{
			{
				prefix: netip.MustParsePrefix("192.168.1.0/24"),
				ifaces: []string{"eth0", "eth1"},
			},
			{
				prefix: netip.MustParsePrefix("10.0.0.0/8"),
				ifaces: []string{"wlan0"},
			},
		},
	}

	tests := []struct {
		name    string
		srcAddr netip.Addr
		txIface string
		allowed bool
	}{
		{"192.168.1.x to eth0 allowed", netip.MustParseAddr("192.168.1.100"), "eth0", true},
		{"192.168.1.x to eth1 allowed", netip.MustParseAddr("192.168.1.50"), "eth1", true},
		{"192.168.1.x to wlan0 blocked", netip.MustParseAddr("192.168.1.100"), "wlan0", false},
		{"192.168.1.x to eth2 blocked", netip.MustParseAddr("192.168.1.1"), "eth2", false},
		{"10.x to wlan0 allowed", netip.MustParseAddr("10.5.3.1"), "wlan0", true},
		{"10.x to eth0 blocked", netip.MustParseAddr("10.5.3.1"), "eth0", false},
		{"unmatched network defaults to allowed", netip.MustParseAddr("172.16.0.1"), "eth0", true},
		{"unmatched network defaults to allowed any iface", netip.MustParseAddr("172.16.0.1"), "wlan0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pr.isAllowedByFilter(tt.srcAddr, tt.txIface)
			if got != tt.allowed {
				t.Errorf("isAllowedByFilter(%s, %s) = %v, want %v",
					tt.srcAddr, tt.txIface, got, tt.allowed)
			}
		})
	}
}

func TestParseIfFilterFile(t *testing.T) {
	t.Run("valid JSON with CIDR", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "filter.json")
		data := map[string][]string{
			"192.168.1.0/24": {"eth0", "eth1"},
			"10.0.0.0/8":     {"wlan0"},
		}
		raw, _ := json.Marshal(data)
		os.WriteFile(path, raw, 0644)

		filters, err := parseIfFilterFile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(filters) != 2 {
			t.Fatalf("expected 2 filters, got %d", len(filters))
		}

		found24 := false
		found8 := false
		for _, f := range filters {
			if f.prefix == netip.MustParsePrefix("192.168.1.0/24") {
				found24 = true
				if len(f.ifaces) != 2 {
					t.Errorf("expected 2 interfaces for /24 filter, got %d", len(f.ifaces))
				}
			}
			if f.prefix == netip.MustParsePrefix("10.0.0.0/8") {
				found8 = true
				if len(f.ifaces) != 1 {
					t.Errorf("expected 1 interface for /8 filter, got %d", len(f.ifaces))
				}
			}
		}
		if !found24 {
			t.Error("missing filter for 192.168.1.0/24")
		}
		if !found8 {
			t.Error("missing filter for 10.0.0.0/8")
		}
	})

	t.Run("no CIDR suffix defaults to /32", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "filter.json")
		data := map[string][]string{
			"192.168.1.1": {"eth0"},
		}
		raw, _ := json.Marshal(data)
		os.WriteFile(path, raw, 0644)

		filters, err := parseIfFilterFile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(filters) != 1 {
			t.Fatalf("expected 1 filter, got %d", len(filters))
		}
		expected := netip.MustParsePrefix("192.168.1.1/32")
		if filters[0].prefix != expected {
			t.Errorf("expected %s prefix, got %s", expected, filters[0].prefix)
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := parseIfFilterFile("/nonexistent/path/filter.json")
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "filter.json")
		os.WriteFile(path, []byte("not json"), 0644)

		_, err := parseIfFilterFile(path)
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("invalid CIDR bits", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "filter.json")
		os.WriteFile(path, []byte(`{"192.168.1.0/abc": ["eth0"]}`), 0644)

		_, err := parseIfFilterFile(path)
		if err == nil {
			t.Error("expected error for invalid CIDR bits")
		}
	})

	t.Run("empty filter map", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "filter.json")
		os.WriteFile(path, []byte(`{}`), 0644)

		filters, err := parseIfFilterFile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(filters) != 0 {
			t.Errorf("expected 0 filters, got %d", len(filters))
		}
	})
}

func TestParseIfFilterFileIntegration(t *testing.T) {
	// End-to-end: parse a filter file, then use isAllowedByFilter
	dir := t.TempDir()
	path := filepath.Join(dir, "filter.json")
	data := map[string][]string{
		"192.168.1.0/24": {"eth0", "eth1"},
	}
	raw, _ := json.Marshal(data)
	os.WriteFile(path, raw, 0644)

	filters, err := parseIfFilterFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pr := &PacketRelay{parsedFilters: filters}

	if !pr.isAllowedByFilter(netip.MustParseAddr("192.168.1.50"), "eth0") {
		t.Error("expected 192.168.1.50 allowed to eth0")
	}
	if pr.isAllowedByFilter(netip.MustParseAddr("192.168.1.50"), "wlan0") {
		t.Error("expected 192.168.1.50 blocked to wlan0")
	}
	if !pr.isAllowedByFilter(netip.MustParseAddr("10.0.0.1"), "wlan0") {
		t.Error("expected 10.0.0.1 allowed to any interface (no matching filter)")
	}
}

// --- Buffer pool tests ---

func TestGetPutBuffer(t *testing.T) {
	bp := getBuffer(100)
	b := *bp
	if len(b) != 100 {
		t.Errorf("getBuffer(100) length = %d, want 100", len(b))
	}
	if cap(b) < 100 {
		t.Errorf("getBuffer(100) capacity = %d, want >= 100", cap(b))
	}
	// Write some data and return to pool
	for i := range b {
		b[i] = byte(i)
	}
	putBuffer(bp)

	// Get another buffer — should reuse from pool
	bp2 := getBuffer(50)
	b2 := *bp2
	if len(b2) != 50 {
		t.Errorf("getBuffer(50) length = %d, want 50", len(b2))
	}
	putBuffer(bp2)
}

func TestGetBufferLargerThanPool(t *testing.T) {
	// Request a buffer larger than the default pool capacity
	bp := getBuffer(maxPacketSize + 1000)
	b := *bp
	if len(b) != maxPacketSize+1000 {
		t.Errorf("getBuffer(%d) length = %d", maxPacketSize+1000, len(b))
	}
	putBuffer(bp)
}

// --- isDuplicate checksumCount clamp branch ---

func TestIsDuplicateChecksumCountClamp(t *testing.T) {
	// Directly set checksumCount beyond maxRecentChecksums to exercise
	// the clamping branch in isDuplicate.
	pr := &PacketRelay{}
	pr.checksumCount = maxRecentChecksums + 10
	pr.recentChecksums[0] = 0xABCD

	// Should still find the value (clamps search to maxRecentChecksums)
	if !pr.isDuplicate(0xABCD) {
		t.Error("expected isDuplicate to find 0xABCD with clamped count")
	}
	// Should not find a value that isn't there
	if pr.isDuplicate(0x1111) {
		t.Error("expected isDuplicate to not find 0x1111")
	}
}

// --- UDP max length alignment test ---

func TestUDPMaxLengthAlignment(t *testing.T) {
	// udpMaxLength must be a multiple of 8 for proper IP fragmentation
	if udpMaxLength%8 != 0 {
		t.Errorf("udpMaxLength=%d is not a multiple of 8", udpMaxLength)
	}
}

// --- removeConnection tests ---

func newTestLogger(t *testing.T) *logger.Logger {
	t.Helper()
	log, err := logger.New(false, "", false)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	return log
}

func TestRemoveConnectionFromRemoteConnections(t *testing.T) {
	pr := &PacketRelay{
		remoteWriters: make(map[net.Conn]*remoteWriter),
	}

	// Create a pair of connected pipes to use as mock connections
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	server2, client2 := net.Pipe()
	defer server2.Close()
	defer client2.Close()

	pr.remoteConnections = []net.Conn{server, server2}

	pr.removeConnection(server)

	if len(pr.remoteConnections) != 1 {
		t.Errorf("expected 1 remaining connection, got %d", len(pr.remoteConnections))
	}
	if pr.remoteConnections[0] != server2 {
		t.Error("wrong connection removed")
	}
}

func TestRemoveConnectionFromRemoteAddrs(t *testing.T) {
	pr := &PacketRelay{
		remoteWriters: make(map[net.Conn]*remoteWriter),
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ra := &RemoteAddr{Addr: "10.0.0.1", Conn: server}
	pr.remoteAddrs = []*RemoteAddr{ra}

	pr.removeConnection(server)

	if ra.Conn != nil {
		t.Error("expected RemoteAddr.Conn to be nil after removal")
	}
	if ra.ConnectFailure.IsZero() {
		t.Error("expected ConnectFailure to be set after removal")
	}
}

func TestIsRemoteBroadcast(t *testing.T) {
	pr := &PacketRelay{
		transmitters: []Transmitter{
			{ // broadcast transmitter: Relay.Addr == Broadcast
				Relay:     RelayAddr{Addr: netip.MustParseAddr("192.168.2.255"), Port: 6969},
				Broadcast: netip.MustParseAddr("192.168.2.255"),
			},
			{ // multicast transmitter: Relay.Addr != Broadcast
				Relay:     RelayAddr{Addr: netip.MustParseAddr("239.255.255.250"), Port: 1900},
				Broadcast: netip.MustParseAddr("192.168.2.255"),
			},
		},
	}

	// A broadcast from another site on the broadcast relay port is recognized.
	if !pr.isRemoteBroadcast(netip.MustParseAddr("192.168.1.255"), 6969) {
		t.Error("expected remote broadcast on port 6969 to be recognized")
	}
	// A multicast destination is never a broadcast.
	if pr.isRemoteBroadcast(netip.MustParseAddr("239.255.255.250"), 1900) {
		t.Error("multicast destination must not be treated as broadcast")
	}
	// A port with no broadcast transmitter is not a broadcast.
	if pr.isRemoteBroadcast(netip.MustParseAddr("192.168.1.255"), 1234) {
		t.Error("unmatched port must not be treated as broadcast")
	}
}

// --- Remote relay protocol tests ---

// minUDPTestPacket builds a minimal 28-byte IPv4/UDP packet for remote-frame tests.
func minUDPTestPacket(src, dst string, sport, dport uint16) []byte {
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45 // version 4, IHL 5
	ipHeader[8] = 64   // TTL
	ipHeader[9] = 17   // UDP protocol
	copy(ipHeader[12:16], net.ParseIP(src).To4())
	copy(ipHeader[16:20], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(ipHeader[2:4], 28) // total length

	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[0:2], sport)
	binary.BigEndian.PutUint16(udpHeader[2:4], dport)
	binary.BigEndian.PutUint16(udpHeader[4:6], 8) // udp length
	return append(ipHeader, udpHeader...)
}

// buildRemoteFrame builds a wire frame (length prefix + body) in the current
// format: seq(8) || magic(4) || senderIP(4) || packet.
func buildRemoteFrame(t *testing.T, aes *cipher.Cipher, seq uint64, sender string, packet []byte) []byte {
	t.Helper()
	senderIP := net.ParseIP(sender).To4()
	plain := make([]byte, 0, 8+len(magicBytes)+4+len(packet))
	var seqB [8]byte
	binary.BigEndian.PutUint64(seqB[:], seq)
	plain = append(plain, seqB[:]...)
	plain = append(plain, magicBytes[:]...)
	plain = append(plain, senderIP...)
	plain = append(plain, packet...)
	frame, err := aes.EncryptFrame(plain)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func newReaderTestRelay(t *testing.T) *PacketRelay {
	t.Helper()
	aes, err := cipher.New("")
	if err != nil {
		t.Fatal(err)
	}
	return &PacketRelay{
		logger:         newTestLogger(t),
		aes:            aes,
		done:           make(chan struct{}),
		remotePacketCh: make(chan remotePacket, 8),
		remoteFailedCh: make(chan net.Conn, 8),
		remoteWriters:  make(map[net.Conn]*remoteWriter),
	}
}

func TestRunReaderValidFrame(t *testing.T) {
	pr := newReaderTestRelay(t)
	defer close(pr.done)

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	packet := minUDPTestPacket("192.168.1.100", "239.255.255.250", 1234, 1900)
	frame := buildRemoteFrame(t, pr.aes, 1, "192.168.1.100", packet)

	pr.startReader(server)
	go func() { client.Write(frame) }()

	select {
	case rp := <-pr.remotePacketCh:
		if rp.senderAddr.String() != "192.168.1.100" {
			t.Errorf("expected sender 192.168.1.100, got %s", rp.senderAddr)
		}
		if len(rp.data) != len(packet) {
			t.Errorf("expected %d-byte packet, got %d", len(packet), len(rp.data))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for decoded packet")
	}
}

func TestRunReaderInvalidMagicSkipped(t *testing.T) {
	pr := newReaderTestRelay(t)
	defer close(pr.done)

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Valid length/seq framing but wrong magic bytes: must be skipped, not fatal.
	packet := minUDPTestPacket("192.168.1.100", "239.255.255.250", 1234, 1900)
	frame := buildRemoteFrame(t, pr.aes, 1, "192.168.1.100", packet)
	// Corrupt the first magic byte (offset: 2 length + 8 seq = 10).
	frame[10] ^= 0xff

	pr.startReader(server)
	go func() { client.Write(frame) }()

	select {
	case <-pr.remotePacketCh:
		t.Error("invalid-magic frame should not be delivered")
	case conn := <-pr.remoteFailedCh:
		t.Errorf("invalid-magic frame should not fail the connection, got %v", conn)
	case <-time.After(300 * time.Millisecond):
		// Expected: nothing delivered, connection stays alive.
	}
}

func TestRunReaderReplayRejected(t *testing.T) {
	pr := newReaderTestRelay(t)
	defer close(pr.done)

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	packet := minUDPTestPacket("192.168.1.100", "239.255.255.250", 1234, 1900)
	pr.startReader(server)

	// seq=5 accepted, replayed seq=5 rejected, seq=6 accepted, older seq=4 rejected.
	go func() {
		client.Write(buildRemoteFrame(t, pr.aes, 5, "192.168.1.100", packet))
		client.Write(buildRemoteFrame(t, pr.aes, 5, "192.168.1.100", packet))
		client.Write(buildRemoteFrame(t, pr.aes, 6, "192.168.1.100", packet))
		client.Write(buildRemoteFrame(t, pr.aes, 4, "192.168.1.100", packet))
	}()

	// Exactly two frames (seq 5 and seq 6) should be delivered.
	deadline := time.After(2 * time.Second)
	got := 0
	for got < 2 {
		select {
		case <-pr.remotePacketCh:
			got++
		case <-deadline:
			t.Fatalf("expected 2 accepted frames, got %d", got)
		}
	}
	// No third frame should arrive.
	select {
	case <-pr.remotePacketCh:
		t.Error("replayed/old frame should not have been delivered")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestRunReaderDeadConnection(t *testing.T) {
	pr := newReaderTestRelay(t)
	defer close(pr.done)

	server, client := net.Pipe()
	defer server.Close()

	pr.startReader(server)
	// Close the client side to simulate a dead connection.
	client.Close()

	select {
	case conn := <-pr.remoteFailedCh:
		if conn != server {
			t.Error("wrong connection reported failed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for dead connection to be reported")
	}
}

// --- Close/shutdown tests ---

func TestCloseSignalsLoop(t *testing.T) {
	pr := &PacketRelay{
		done:          make(chan struct{}),
		remoteWriters: make(map[net.Conn]*remoteWriter),
	}

	pr.Close()

	// done channel should be closed
	select {
	case <-pr.done:
		// good
	default:
		t.Error("expected done channel to be closed after Close()")
	}

	// Calling Close again should not panic
	pr.Close()
}

func TestRemoteSocketsCollectsAll(t *testing.T) {
	pr := &PacketRelay{connsDirty: true}

	server1, client1 := net.Pipe()
	defer server1.Close()
	defer client1.Close()

	server2, client2 := net.Pipe()
	defer server2.Close()
	defer client2.Close()

	pr.remoteConnections = []net.Conn{server1}
	pr.remoteAddrs = []*RemoteAddr{
		{Addr: "10.0.0.1", Conn: server2},
		{Addr: "10.0.0.2", Conn: nil}, // not connected
	}

	conns := pr.remoteSockets()
	if len(conns) != 2 {
		t.Errorf("expected 2 connections, got %d", len(conns))
	}
}

func TestMaxRemoteMessageLenFitsMaxPacket(t *testing.T) {
	aes, err := cipher.New("test-key")
	if err != nil {
		t.Fatal(err)
	}

	// Worst-case remote relay payload: seq + magic + senderIP + max-size packet.
	payload := make([]byte, 0, remoteHeaderLen+maxPacketSize)
	payload = append(payload, make([]byte, remoteHeaderLen)...)
	payload = append(payload, make([]byte, maxPacketSize)...)

	frame, err := aes.EncryptFrame(payload)
	if err != nil {
		t.Fatalf("EncryptFrame() error = %v", err)
	}

	bodyLen := int(binary.BigEndian.Uint16(frame[:2]))
	if bodyLen > maxRemoteMessageLen {
		t.Errorf("max-size frame body = %d exceeds maxRemoteMessageLen = %d; the receiving peer would reject it and drop the connection", bodyLen, maxRemoteMessageLen)
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func TestRemoteMutualAuthHandshake(t *testing.T) {
	port := freeTCPPort(t)

	newRelay := func(key string, listen, remote []string) *PacketRelay {
		pr, err := New(Config{
			Listen:      listen,
			Remote:      remote,
			RemotePort:  port,
			RemoteRetry: 1,
			AESKey:      key,
			Logger:      newTestLogger(t),
		})
		if err != nil {
			t.Fatal(err)
		}
		return pr
	}

	t.Run("matching keys complete handshake", func(t *testing.T) {
		server := newRelay("shared-secret", []string{"127.0.0.1"}, nil)
		defer server.Close()
		client := newRelay("shared-secret", nil, []string{"127.0.0.1"})
		defer client.Close()

		go client.dialRemote(client.remoteAddrs[0])

		select {
		case conn := <-server.acceptCh:
			conn.Close()
		case <-time.After(3 * time.Second):
			t.Fatal("server did not accept an authenticated connection")
		}
		select {
		case res := <-client.connectResultCh:
			if res.err != nil {
				t.Fatalf("client handshake failed: %v", res.err)
			}
			if res.conn != nil {
				res.conn.Close()
			}
		case <-time.After(3 * time.Second):
			t.Fatal("client dial produced no result")
		}
	})

	t.Run("mismatched key is rejected", func(t *testing.T) {
		server := newRelay("right-key", []string{"127.0.0.1"}, nil)
		defer server.Close()
		client := newRelay("wrong-key", nil, []string{"127.0.0.1"})
		defer client.Close()

		go client.dialRemote(client.remoteAddrs[0])

		// The server must not hand up an authenticated connection.
		select {
		case conn := <-server.acceptCh:
			conn.Close()
			t.Fatal("server accepted a connection with the wrong key")
		case <-time.After(500 * time.Millisecond):
		}
		// The client dial must report an error rather than a usable connection.
		select {
		case res := <-client.connectResultCh:
			if res.err == nil {
				t.Fatal("client accepted a server it could not authenticate")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("client dial produced no result")
		}
	})
}

func TestDialRemoteReturnsAfterClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	aes, err := cipher.New("")
	if err != nil {
		t.Fatal(err)
	}

	pr := &PacketRelay{
		logger:          newTestLogger(t),
		aes:             aes,
		connectResultCh: make(chan connectResult), // unbuffered: nothing drains it after Loop() exits
		done:            make(chan struct{}),
		remotePort:      ln.Addr().(*net.TCPAddr).Port,
	}
	close(pr.done) // simulate relay shut down while the dial is in flight

	returned := make(chan struct{})
	go func() {
		pr.dialRemote(&RemoteAddr{Addr: "127.0.0.1"})
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(3 * time.Second):
		t.Fatal("dialRemote blocked forever after relay close (goroutine leak)")
	}
}

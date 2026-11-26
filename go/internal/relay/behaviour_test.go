package relay

import (
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// ssdpTransmitter returns a transmitter for the SSDP group whose frames can be
// read from the returned fd.
func ssdpTransmitter(t *testing.T, name, addr string) (Transmitter, int) {
	t.Helper()
	tx, out := socketTransmitter(t, name, addr)
	tx.Relay = RelayAddr{Addr: ssdpMcastNetip, Port: SSDPMcastPort}
	return tx, out
}

// ssdpPacket builds an SSDP packet with the given payload.
func ssdpPacket(src, dst string, payload string) []byte {
	p := append(minUDPTestPacket(src, dst, 1234, 1900), payload...)
	p[2], p[3] = byte(len(p)>>8), byte(len(p))
	p[24], p[25] = byte((len(p)-20)>>8), byte(len(p)-20)
	ComputeIPChecksum(p, 20)
	return p
}

func sentCount(fd int) (n int) {
	buf := make([]byte, 2000)
	for {
		if _, err := unix.Read(fd, buf); err != nil {
			return n
		}
		n++
	}
}

func newLocalTestRelay(t *testing.T, txs ...Transmitter) *PacketRelay {
	t.Helper()
	pr := newReaderTestRelay(t)
	pr.etherAddrs = map[netip.Addr]net.HardwareAddr{
		ssdpMcastNetip: MulticastIPToMAC(SSDPMcastAddr),
		broadcastIP:    BroadcastIPToMAC(),
	}
	pr.transmitters = txs
	listenOn(pr, txs...)
	addRule(pr, SSDPMcastAddr, SSDPMcastPort)
	return pr
}

func TestIfFilterMostSpecificRuleWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filter.json")
	rules := `{"10.0.0.0/8":["br0","br50"],"10.0.1.0/24":["br0","br50"],"10.0.1.5":["br0"]}`
	if err := os.WriteFile(path, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 200 {
		filters, err := parseIfFilterFile(path)
		if err != nil {
			t.Fatal(err)
		}
		pr := &PacketRelay{parsedFilters: filters}
		if pr.isAllowedByFilter(netip.MustParseAddr("10.0.1.5"), "br50") {
			t.Fatal("restricted host allowed onto br50")
		}
		if !pr.isAllowedByFilter(netip.MustParseAddr("10.0.2.9"), "br50") {
			t.Fatal("host covered only by the broad rule was refused")
		}
	}
}

func TestIfFilterRejectsTwoRulesForOneRange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filter.json")
	if err := os.WriteFile(path, []byte(`{"10.0.1.5":["br0"],"10.0.1.5/32":["br50"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseIfFilterFile(path); err == nil {
		t.Error("two rules for the same range were accepted")
	}
}

func TestRemotePacketIsNotEchoedToItsSource(t *testing.T) {
	pr := newReaderTestRelay(t)
	defer close(pr.done)
	fromServer, fromPeer := net.Pipe()
	otherServer, otherPeer := net.Pipe()
	for _, c := range []net.Conn{fromServer, fromPeer, otherServer, otherPeer} {
		defer c.Close()
	}
	pr.connectedRemotes = []net.Conn{fromServer, otherServer}

	pr.startReader(fromServer)
	frame := buildRemoteFrame(t, pr.aes, 1, "192.168.1.100",
		minUDPTestPacket("192.168.1.100", "239.255.255.250", 1234, 1900))
	if _, err := fromPeer.Write(frame); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(pr.remotePacketCh) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("frame was not decoded")
		}
		time.Sleep(5 * time.Millisecond)
	}
	pr.drainRemotePackets()

	otherPeer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(otherPeer, make([]byte, len(frame))); err != nil {
		t.Fatalf("other peer did not receive the packet: %v", err)
	}
	fromPeer.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _ := fromPeer.Read(make([]byte, 100)); n != 0 {
		t.Error("packet was sent back to the peer it came from")
	}
}

func TestSlowRemotePeerKeepsItsConnection(t *testing.T) {
	pr := newReaderTestRelay(t)
	defer close(pr.done)
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()

	pr.queueRemoteFrame(server, []byte("frame"))
	time.Sleep(500 * time.Millisecond) // a short stall on a slow link

	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(peer, make([]byte, 7)); err != nil {
		t.Fatalf("frame lost after a 500 ms stall: %v", err)
	}
}

func TestRemoteForwardsOnlyRelayedTraffic(t *testing.T) {
	pr := newLocalTestRelay(t)
	defer close(pr.done)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	pr.connectedRemotes = []net.Conn{local}
	sender := netip.MustParseAddr("192.168.1.100")

	// A raw receive socket also sees other ports, which must stay on this site.
	deliver(pr, minUDPTestPacket("192.168.1.100", "255.255.255.255", 68, 67), sender, "local")
	deliver(pr, minUDPTestPacket("192.168.1.100", "239.255.255.250", 1234, 9999), sender, "local")
	if pr.remoteSeq != 0 {
		t.Errorf("unrelayed traffic forwarded %d times", pr.remoteSeq)
	}
	deliver(pr, minUDPTestPacket("192.168.1.100", "239.255.255.250", 1234, 1900), sender, "local")
	if pr.remoteSeq != 1 {
		t.Errorf("relayed traffic forwarded %d times, want 1", pr.remoteSeq)
	}
}

func TestDuplicateFilterLooksAtContent(t *testing.T) {
	a, _ := socketTransmitter(t, "a", "192.168.1.1")
	b, out := ssdpTransmitter(t, "b", "192.168.2.1")
	pr := newLocalTestRelay(t, a, b)
	sender := netip.MustParseAddr("192.168.1.100")
	send := func(payload string) {
		deliver(pr, ssdpPacket("192.168.1.100", SSDPMcastAddr, payload), sender, "local")
	}

	// Identical IP headers, as sent by a device that never changes its packet ID.
	send("first message")
	send("other message")
	if got := sentCount(out); got != 2 {
		t.Errorf("two different messages relayed %d times, want 2", got)
	}
	send("first message")
	if got := sentCount(out); got != 0 {
		t.Errorf("immediate repeat relayed %d times, want 0", got)
	}
}

func TestSSDPAnnouncementDoesNotReplaceSearcher(t *testing.T) {
	pr := newReaderTestRelay(t)
	pr.ssdpUnicastAddr = netip.MustParseAddr("192.168.2.1")
	for src, payload := range map[string]string{"192.168.1.10": "M-SEARCH * HTTP/1.1"} {
		p := ssdpPacket(src, SSDPMcastAddr, payload)
		pr.handleSSDP(p, 20, netip.MustParseAddr(src), 1234, ssdpMcastNetip, SSDPMcastPort)
	}
	notify := ssdpPacket("192.168.1.99", SSDPMcastAddr, "NOTIFY * HTTP/1.1")
	out, src, _, _, _, _, drop := pr.handleSSDP(notify, 20, netip.MustParseAddr("192.168.1.99"), 1900, ssdpMcastNetip, SSDPMcastPort)

	if got := pr.ssdpSrc.addr.String(); got != "192.168.1.10" {
		t.Errorf("reply target = %s, want the searcher 192.168.1.10", got)
	}
	if drop || src.String() != "192.168.1.99" || AddrFrom4Bytes(out[12:16]).String() != "192.168.1.99" {
		t.Error("announcement must be relayed unchanged")
	}
}

func TestIfFilterAppliesToTheRealSearcher(t *testing.T) {
	a, _ := socketTransmitter(t, "a", "192.168.1.1")
	b, bOut := ssdpTransmitter(t, "b", "192.168.2.1")
	c, cOut := ssdpTransmitter(t, "c", "192.168.3.1")
	pr := newLocalTestRelay(t, a, b, c)
	pr.ssdpUnicastAddr = netip.MustParseAddr("192.168.2.1")
	pr.parsedFilters = []parsedFilter{{prefix: netip.MustParsePrefix("192.168.1.10/32"), ifaces: []string{"b"}}}

	deliver(pr, ssdpPacket("192.168.1.10", SSDPMcastAddr, "M-SEARCH * HTTP/1.1"),
		netip.MustParseAddr("192.168.1.10"), "local")

	if got := sentCount(bOut); got != 1 {
		t.Errorf("permitted network received %d searches, want 1", got)
	}
	if got := sentCount(cOut); got != 0 {
		t.Errorf("filtered network received %d searches, want 0", got)
	}
}

func TestOneInterfaceRelaysOnlyFromTheSecondNetwork(t *testing.T) {
	eth, out := ssdpTransmitter(t, "eth0", "192.168.1.1")
	pr := newLocalTestRelay(t, eth)
	pr.oneInterface = true

	deliver(pr, ssdpPacket("192.168.9.10", SSDPMcastAddr, "from the second network"),
		netip.MustParseAddr("192.168.9.10"), "local")
	if got := sentCount(out); got != 1 {
		t.Errorf("second network relayed %d times, want 1", got)
	}
	deliver(pr, ssdpPacket("192.168.1.10", SSDPMcastAddr, "from the first network"),
		netip.MustParseAddr("192.168.1.10"), "local")
	if got := sentCount(out); got != 0 {
		t.Errorf("first network echoed %d times, want 0", got)
	}
}

func TestSendFailureIsLoggedOnceUntilItRecovers(t *testing.T) {
	a, _ := socketTransmitter(t, "a", "192.168.1.1")
	b, _ := ssdpTransmitter(t, "b", "192.168.2.1")
	pr := newLocalTestRelay(t, a, b)
	logRelay, path := newFileLogRelay(t)
	pr.logger = logRelay.logger
	send := func(payload string) {
		deliver(pr, ssdpPacket("192.168.1.100", SSDPMcastAddr, payload),
			netip.MustParseAddr("192.168.1.100"), "local")
	}
	count := func(what string) int {
		log, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Count(string(log), what)
	}

	working := pr.transmitters[1].Socket
	pr.transmitters[1].Socket = -1 // as when the interface has gone
	send("one")
	send("two")
	send("three")
	if got := count("Error sending packet on b"); got != 1 {
		t.Errorf("failure logged %d times, want 1", got)
	}
	pr.transmitters[1].Socket = working
	send("four")
	send("five")
	if got := count("Sending on b works again"); got != 1 {
		t.Errorf("recovery logged %d times, want 1", got)
	}
}

func TestHostPacketsAreNotCopiedBetweenLocalNetworks(t *testing.T) {
	a, _ := socketTransmitter(t, "a", "192.168.1.1")
	b, out := ssdpTransmitter(t, "b", "192.168.2.1")
	pr := newLocalTestRelay(t, a, b)
	defer close(pr.done)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	pr.connectedRemotes = []net.Conn{local}
	own := netip.MustParseAddr("192.168.1.1")

	deliver(pr, ssdpPacket("192.168.1.1", SSDPMcastAddr, "from this host"), own, "local")
	if got := sentCount(out); got != 0 {
		t.Errorf("host's own packet copied %d times, want 0", got)
	}
	// The host has no interface on a remote site, so that site still needs it.
	if pr.remoteSeq != 1 {
		t.Errorf("host's own packet forwarded to remotes %d times, want 1", pr.remoteSeq)
	}
	// A remote site may use the same addresses as this one.
	deliver(pr, ssdpPacket("192.168.1.1", SSDPMcastAddr, "from a remote site"), own, "remote")
	if got := sentCount(out); got != 1 {
		t.Errorf("remote packet relayed %d times, want 1", got)
	}
}

func TestCloseLeavesSocketCleanUpToLoop(t *testing.T) {
	tx, _ := socketTransmitter(t, "a", "192.168.1.1")
	fd, err := unix.Dup(tx.Socket)
	if err != nil {
		t.Fatal(err)
	}
	tx.Socket = fd
	pr := newReaderTestRelay(t)
	pr.transmitters = []Transmitter{tx}
	isOpen := func() bool {
		_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		return err == nil
	}

	pr.Close()
	if !isOpen() {
		t.Fatal("Close closed a socket the loop may still be using")
	}
	if err := pr.Loop(); err != nil {
		t.Fatal(err)
	}
	if isOpen() {
		t.Error("Loop returned without closing its sockets")
	}
}

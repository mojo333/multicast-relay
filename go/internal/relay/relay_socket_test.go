package relay

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// socketTransmitter returns a transmitter whose frames can be read from the returned fd.
func socketTransmitter(t *testing.T, name, addr string) (Transmitter, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fds[0]); unix.Close(fds[1]) })
	ip := netip.MustParseAddr(addr)
	b := ip.As4()
	b[3] = 255
	bcast := netip.AddrFrom4(b)
	return Transmitter{
		Relay: RelayAddr{Addr: bcast, Port: 6969}, Interface: name, Addr: ip,
		MAC: net.HardwareAddr{0, 0, 0, 0, 0, 0}, Network: netip.PrefixFrom(ip, 24).Masked(),
		Broadcast: bcast, Socket: fds[0],
	}, fds[1]
}

func TestBroadcastIsReaddressedPerInterface(t *testing.T) {
	for _, source := range []string{"local", "remote"} {
		t.Run(source, func(t *testing.T) {
			pr := newReaderTestRelay(t)
			pr.etherAddrs = map[netip.Addr]net.HardwareAddr{broadcastIP: BroadcastIPToMAC()}
			rx, _ := socketTransmitter(t, "a", "192.168.1.1")
			b, bOut := socketTransmitter(t, "b", "192.168.2.1")
			c, cOut := socketTransmitter(t, "c", "192.168.3.1")
			pr.transmitters = []Transmitter{rx, b, c}
			listenOn(pr, pr.transmitters...)

			// A remote sender sits on a subnet that no local interface owns.
			src, dst := "192.168.1.100", "192.168.1.255"
			if source == "remote" {
				src, dst = "10.0.0.100", "10.0.0.255"
			}
			packet := minUDPTestPacket(src, dst, 1234, 6969)
			ComputeIPChecksum(packet, 20)
			pr.processPacket(packet, netip.MustParseAddr(src), source, nil)

			for _, out := range []struct {
				fd   int
				want netip.Addr
			}{{bOut, b.Broadcast}, {cOut, c.Broadcast}} {
				buf := make([]byte, 1500)
				n, err := unix.Read(out.fd, buf)
				if err != nil {
					t.Fatalf("nothing transmitted towards %s: %v", out.want, err)
				}
				sent := buf[:n]
				if got := AddrFrom4Bytes(sent[16:20]); got != out.want {
					t.Errorf("destination = %s, want %s", got, out.want)
				}
				zeroed := append([]byte(nil), sent[20:28]...)
				binary.BigEndian.PutUint16(zeroed[6:8], 0)
				if want := ComputeUDPChecksum(sent[:20], zeroed, sent[28:]); !bytes.Equal(want, sent[20:28]) {
					t.Errorf("UDP checksum does not match the rewritten destination")
				}
			}
		})
	}
}

func TestInterfaceWithoutIPv4CanBeWaitedFor(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	name := ""
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		hasIPv4 := false
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
				hasIPv4 = true
			}
		}
		if !hasIPv4 {
			name = iface.Name
			break
		}
	}
	if name == "" {
		t.Skip("every interface on this host has an IPv4 address")
	}

	result, err := resolveInterface(name)
	if err != nil {
		t.Fatalf("resolveInterface(%q) = %v, want a result with no address", name, err)
	}
	if result.Name != name || result.Addr.IsValid() {
		t.Errorf("got name %q addr %v", result.Name, result.Addr)
	}

	pr := newReaderTestRelay(t)
	if _, err := pr.resolveInterfaceWait(name, false); err == nil || !strings.Contains(err.Error(), "does not have an IPv4") {
		t.Errorf("without --wait: err = %v", err)
	}
	close(pr.done)
	if _, err := pr.resolveInterfaceWait(name, true); err == nil || !strings.Contains(err.Error(), "shutting down") {
		t.Errorf("with --wait: err = %v, want the wait loop to be entered", err)
	}
}

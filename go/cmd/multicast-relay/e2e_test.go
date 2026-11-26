package main

// End-to-end tests: real relay processes on virtual networks.
//
// They need root and iproute2, so they only run when MULTICAST_RELAY_E2E=1. Once
// asked for, a set-up that cannot be built is a failure rather than a skip.
//
//	go test -exec "sudo env MULTICAST_RELAY_E2E=1" ./cmd/... -run EndToEnd -v -count=1

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// roleEnv makes the test binary act as the relay or as a host on a virtual network.
const roleEnv = "MCR_E2E_ROLE"

const (
	mdnsGroup = "224.0.0.251"
	ssdpGroup = "239.255.255.250"
	listenFor = 1200 * time.Millisecond
)

func TestMain(m *testing.M) {
	switch os.Getenv(roleEnv) {
	case "relay":
		os.Exit(run())
	case "receive":
		hostReceive(os.Args[1:])
	case "send":
		hostSend(os.Args[1:])
	case "respond":
		hostRespond(os.Args[1])
	case "search":
		hostSearch(os.Args[1])
	default:
		os.Exit(m.Run())
	}
	os.Exit(0)
}

// ---------- what runs on a virtual host ----------

func check(err error) {
	if err != nil {
		fmt.Println("ERROR", err)
		os.Exit(1)
	}
}

func ip4(s string) [4]byte { return netip.MustParseAddr(s).As4() }

func udpSocket() int {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	check(err)
	check(unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1))
	return fd
}

func join(fd int, group, ifIP string) {
	check(unix.SetsockoptIPMreq(fd, unix.SOL_IP, unix.IP_ADD_MEMBERSHIP,
		&unix.IPMreq{Multiaddr: ip4(group), Interface: ip4(ifIP)}))
}

func setTimeout(fd int, d time.Duration) {
	tv := unix.NsecToTimeval(d.Nanoseconds())
	check(unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv))
}

// hostReceive prints one "payload-prefix source-ip" line per datagram.
// Arguments: group-or-0.0.0.0 port interface-ip milliseconds.
func hostReceive(args []string) {
	group, ifIP := args[0], args[2]
	port, _ := strconv.Atoi(args[1])
	millis, _ := strconv.Atoi(args[3])

	fd := udpSocket()
	check(unix.Bind(fd, &unix.SockaddrInet4{Port: port, Addr: ip4(group)}))
	if group != "0.0.0.0" {
		join(fd, group, ifIP)
	}
	fmt.Println("READY")
	buf := make([]byte, 65536)
	end := time.Now().Add(time.Duration(millis) * time.Millisecond)
	for time.Now().Before(end) {
		setTimeout(fd, max(time.Until(end), time.Millisecond))
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return
		}
		sa := from.(*unix.SockaddrInet4)
		fmt.Println(strings.TrimRight(string(buf[:min(n, 12)]), "."), netip.AddrFrom4(sa.Addr))
	}
}

func senderSocket(ifIP string, port int) int {
	fd := udpSocket()
	check(unix.BindToDevice(fd, "eth0"))
	check(unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1))
	check(unix.SetsockoptInet4Addr(fd, unix.SOL_IP, unix.IP_MULTICAST_IF, ip4(ifIP)))
	check(unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_MULTICAST_TTL, 4))
	check(unix.Bind(fd, &unix.SockaddrInet4{Port: port, Addr: ip4(ifIP)}))
	return fd
}

// hostSend sends one datagram. Arguments: source-ip destination port size tag.
func hostSend(args []string) {
	port, _ := strconv.Atoi(args[2])
	size, _ := strconv.Atoi(args[3])
	fd := senderSocket(args[0], 40000)
	body := []byte(args[4] + strings.Repeat(".", size-len(args[4])))
	check(unix.Sendto(fd, body, 0, &unix.SockaddrInet4{Port: port, Addr: ip4(args[1])}))
}

// hostRespond answers one SSDP search, as a device would.
func hostRespond(ifIP string) {
	fd := udpSocket()
	check(unix.Bind(fd, &unix.SockaddrInet4{Port: 1900, Addr: ip4(ssdpGroup)}))
	join(fd, ssdpGroup, ifIP)
	setTimeout(fd, 4*time.Second)
	fmt.Println("READY")
	buf := make([]byte, 2048)
	_, from, err := unix.Recvfrom(fd, buf, 0)
	check(err)
	check(unix.Sendto(udpSocket(), []byte("HTTP/1.1 200 OK"), 0, from))
}

// hostSearch sends an SSDP search and prints the reply.
func hostSearch(ifIP string) {
	fd := senderSocket(ifIP, 40001)
	check(unix.Sendto(fd, []byte("M-SEARCH * HTTP/1.1\r\n"), 0, &unix.SockaddrInet4{Port: 1900, Addr: ip4(ssdpGroup)}))
	setTimeout(fd, 3*time.Second)
	buf := make([]byte, 2048)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	check(err)
	fmt.Println(string(buf[:n]))
}

// ---------- the virtual networks ----------

type lab struct {
	t    *testing.T
	self string
}

func (l lab) ns(name string) string { return fmt.Sprintf("mcr%d-%s", os.Getpid(), name) }

func (l lab) ip(args string) {
	l.t.Helper()
	if out, err := exec.Command("ip", strings.Fields(args)...).CombinedOutput(); err != nil {
		l.t.Fatalf("ip %s: %v: %s", args, err, out)
	}
}

func (l lab) addNS(name string) {
	l.t.Helper()
	ns := l.ns(name)
	l.ip("netns add " + ns)
	l.t.Cleanup(func() {
		exec.Command("ip", "netns", "del", ns).Run()
	})
	l.ip("-n " + ns + " link set lo up")
	out, err := exec.Command("ip", "netns", "exec", ns, "sh", "-c",
		"for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $f; done").CombinedOutput()
	if err != nil {
		l.t.Fatalf("cannot disable rp_filter: %v: %s", err, out)
	}
}

// link joins relayNS (interface ifName, .1) to host (interface eth0, .2).
func (l lab) link(relayNS, ifName, host, subnet string) {
	l.t.Helper()
	r, h := l.ns(relayNS), l.ns(host)
	l.ip(fmt.Sprintf("link add %s netns %s type veth peer name eth0 netns %s", ifName, r, h))
	l.ip(fmt.Sprintf("-n %s addr add %s.1/24 broadcast + dev %s", r, subnet, ifName))
	l.ip(fmt.Sprintf("-n %s link set %s up", r, ifName))
	l.ip(fmt.Sprintf("-n %s addr add %s.2/24 broadcast + dev eth0", h, subnet))
	l.ip(fmt.Sprintf("-n %s link set eth0 up", h))
	l.ip(fmt.Sprintf("-n %s route replace default via %s.1", h, subnet))
}

// newLab builds a relay namespace with interfaces r0-r2, each facing a host h0-h2
// on 10.77.N.0/24.
func newLab(t *testing.T) lab {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	l := lab{t: t, self: self}
	l.addNS("relay")
	for n := range 3 {
		host := fmt.Sprintf("h%d", n)
		l.addNS(host)
		l.link("relay", fmt.Sprintf("r%d", n), host, fmt.Sprintf("10.77.%d", n))
	}
	time.Sleep(200 * time.Millisecond)
	return l
}

func (l lab) command(ns, role string, args ...string) *exec.Cmd {
	cmd := exec.Command("ip", append([]string{"netns", "exec", l.ns(ns), l.self}, args...)...)
	cmd.Env = append(os.Environ(), roleEnv+"="+role)
	return cmd
}

type proc struct {
	t       *testing.T
	logPath string
	exited  chan error
}

func (p proc) log() string {
	b, _ := os.ReadFile(p.logPath)
	return string(b)
}

// relay starts a relay and waits until its sockets are open.
func (l lab) relay(ns, args string, env ...string) proc {
	l.t.Helper()
	dir := l.t.TempDir()
	logPath, monitor := filepath.Join(dir, "relay.log"), filepath.Join(dir, "monitor.log")
	out, err := os.Create(logPath)
	if err != nil {
		l.t.Fatal(err)
	}
	cmd := l.command(ns, "relay", append(strings.Fields(args), "--foreground", "--verbose", "--monitor", monitor)...)
	cmd.Env = append(cmd.Env, env...)
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		l.t.Fatal(err)
	}
	p := proc{t: l.t, logPath: logPath, exited: make(chan error, 1)}
	done := make(chan struct{})
	go func() { p.exited <- cmd.Wait(); close(done) }()
	l.t.Cleanup(func() {
		select {
		case <-done: // the scenario expected it to exit, or start-up failed
		default:
			// Every relay must also shut down cleanly.
			cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
				if !cmd.ProcessState.Success() {
					l.t.Errorf("relay %q did not shut down cleanly: %s", args, cmd.ProcessState)
				}
			case <-time.After(5 * time.Second):
				l.t.Errorf("relay %q ignored SIGTERM", args)
				cmd.Process.Kill()
				<-done
			}
		}
		if strings.Contains(p.log(), "DATA RACE") {
			l.t.Errorf("relay %q reported a data race", args)
		}
		out.Close()
		if l.t.Failed() {
			l.t.Logf("relay %q log:\n%s", args, p.log())
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if b, _ := os.ReadFile(monitor); strings.Contains(string(b), "Relay active") {
			time.Sleep(200 * time.Millisecond)
			return p
		}
		select {
		case <-done:
			l.t.Fatalf("relay %q exited during start-up:\n%s", args, p.log())
		default:
		}
		if time.Now().After(deadline) {
			l.t.Fatalf("relay %q did not start:\n%s", args, p.log())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// start launches a host helper, waits for READY and returns a function that
// collects the rest of its output.
func (l lab) start(ns, role string, args ...string) func() []string {
	l.t.Helper()
	cmd := l.command(ns, role, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		l.t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		l.t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "READY" {
		l.t.Fatalf("%s helper in %s: %q", role, ns, scanner.Text())
	}
	return func() []string {
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		cmd.Wait()
		return lines
	}
}

func (l lab) send(host, srcIP, dst string, port, size int, tag string) {
	l.t.Helper()
	out, err := l.command(host, "send", srcIP, dst, strconv.Itoa(port), strconv.Itoa(size), tag).CombinedOutput()
	if err != nil {
		l.t.Fatalf("send from %s: %v: %s", host, err, out)
	}
}

var tagCounter int

// delivered sends one datagram from host "from" and reports what host "to" got.
func (l lab) delivered(from int, dst string, port, to int) []string {
	l.t.Helper()
	return l.deliveredFrom(from, fmt.Sprintf("10.77.%d.2", from), dst, port, to)
}

func (l lab) deliveredFrom(from int, srcIP, dst string, port, to int) []string {
	l.t.Helper()
	group := "0.0.0.0"
	if strings.HasPrefix(dst, "224.") || strings.HasPrefix(dst, "239.") {
		group = dst
	}
	collect := l.start(fmt.Sprintf("h%d", to), "receive", group, strconv.Itoa(port),
		fmt.Sprintf("10.77.%d.2", to), strconv.Itoa(int(listenFor.Milliseconds())))
	tagCounter++
	tag := fmt.Sprintf("t%05d", tagCounter)
	// A distinct size keeps the duplicate filter out of the picture.
	l.send(fmt.Sprintf("h%d", from), srcIP, dst, port, 100+tagCounter, tag)
	var got []string
	for _, line := range collect() {
		if strings.HasPrefix(line, tag) {
			got = append(got, line)
		}
	}
	return got
}

func (l lab) want(count int, what string, got []string) {
	l.t.Helper()
	if len(got) != count {
		l.t.Errorf("%s: delivered %d times %v, want %d", what, len(got), got, count)
	}
}

func (l lab) recreate(ifName string, n int) {
	l.t.Helper()
	l.ip("-n " + l.ns("relay") + " link del " + ifName)
	time.Sleep(300 * time.Millisecond)
	l.link("relay", ifName, fmt.Sprintf("h%d", n), fmt.Sprintf("10.77.%d", n))
}

// eventually repeats a delivery until it succeeds or the time is up.
func (l lab) eventually(what string, try func() []string) {
	l.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for len(try()) == 0 {
		if time.Now().After(deadline) {
			l.t.Errorf("%s: nothing delivered within 10 s", what)
			return
		}
	}
}

// ---------- scenarios ----------

func TestEndToEnd(t *testing.T) {
	if os.Getenv("MULTICAST_RELAY_E2E") != "1" {
		t.Skip("set MULTICAST_RELAY_E2E=1 and run as root to enable")
	}
	if os.Geteuid() != 0 {
		t.Fatal("end-to-end tests need root")
	}
	const base = "--interfaces r0 --interfaces r1"
	const bcast0, bcast1 = "10.77.0.255", "10.77.1.255"
	const limited = "255.255.255.255"

	t.Run("relays multicast and subnet broadcast", func(t *testing.T) {
		l := newLab(t)
		l.relay("relay", base)
		l.want(1, "mDNS h0 to h1", l.delivered(0, mdnsGroup, 5353, 1))
		l.want(1, "mDNS h1 to h0", l.delivered(1, mdnsGroup, 5353, 0))
		l.want(1, "subnet broadcast", l.delivered(0, bcast0, 6969, 1))
	})

	t.Run("relays limited broadcast", func(t *testing.T) {
		l := newLab(t)
		l.relay("relay", base)
		l.want(1, "255.255.255.255", l.delivered(0, limited, 6969, 1))
	})

	t.Run("relays a link-local sender on a listed network", func(t *testing.T) {
		l := newLab(t)
		l.ip("-n " + l.ns("h0") + " addr add 169.254.9.2/16 dev eth0")
		l.relay("relay", base)
		l.want(1, "mDNS from 169.254.9.2", l.deliveredFrom(0, "169.254.9.2", mdnsGroup, 5353, 1))
	})

	t.Run("ignores networks that were not listed", func(t *testing.T) {
		l := newLab(t)
		l.relay("relay", base)
		// Another program on the relay host joins the group on the unlisted network.
		other := l.start("relay", "receive", mdnsGroup, "5353", "10.77.2.1", "4000")
		defer other()
		l.want(0, "mDNS from unlisted r2", l.delivered(2, mdnsGroup, 5353, 1))
		l.want(0, "limited broadcast from unlisted r2", l.delivered(2, limited, 6969, 1))
	})

	for _, spec := range []string{"r0", "10.77.0.1"} {
		t.Run("listen-only "+spec+" relays broadcast", func(t *testing.T) {
			l := newLab(t)
			l.relay("relay", base+" --noTransmitInterfaces "+spec)
			l.want(1, "subnet broadcast from listen-only", l.delivered(0, bcast0, 6969, 1))
			l.want(1, "limited broadcast from listen-only", l.delivered(0, limited, 6969, 1))
			l.want(0, "multicast towards listen-only", l.delivered(1, mdnsGroup, 5353, 0))
			l.want(0, "broadcast towards listen-only", l.delivered(1, bcast1, 6969, 0))
		})
	}

	t.Run("list options accept several values", func(t *testing.T) {
		l := newLab(t)
		l.relay("relay", base+" --noTransmitInterfaces r0 r2")
		l.want(0, "r2 must not become a relayed interface", l.delivered(2, mdnsGroup, 5353, 1))
		l.want(1, "r0 to r1", l.delivered(0, mdnsGroup, 5353, 1))
		l.want(0, "r1 to listen-only r0", l.delivered(1, mdnsGroup, 5353, 0))
	})

	t.Run("recovers after an interface is recreated", func(t *testing.T) {
		l := newLab(t)
		l.relay("relay", base)
		l.want(1, "before", l.delivered(1, mdnsGroup, 5353, 0))
		l.recreate("r1", 1)
		l.eventually("multicast from the new r1", func() []string { return l.delivered(1, mdnsGroup, 5353, 0) })
		l.want(1, "multicast to the new r1", l.delivered(0, mdnsGroup, 5353, 1))
		l.want(1, "broadcast from the new r1", l.delivered(1, bcast1, 6969, 0))
		l.want(1, "limited broadcast from the new r1", l.delivered(1, limited, 6969, 0))
	})

	t.Run("recovers a recreated listen-only interface", func(t *testing.T) {
		l := newLab(t)
		l.relay("relay", base+" --noTransmitInterfaces r0")
		l.recreate("r0", 0)
		l.eventually("multicast from the new r0", func() []string { return l.delivered(0, mdnsGroup, 5353, 1) })
	})

	for _, spec := range []string{"10.77.1.1", "10.77.1.0/24"} {
		t.Run("follows an interface listed as "+spec+" to a new address", func(t *testing.T) {
			l := newLab(t)
			l.relay("relay", "--interfaces r0 --interfaces "+spec)
			l.want(1, "before", l.delivered(1, bcast1, 6969, 0))
			r, h := l.ns("relay"), l.ns("h1")
			l.ip("-n " + r + " addr del 10.77.1.1/24 dev r1")
			l.ip("-n " + r + " addr add 10.77.5.1/24 broadcast + dev r1")
			l.ip("-n " + h + " addr del 10.77.1.2/24 dev eth0")
			l.ip("-n " + h + " addr add 10.77.5.2/24 broadcast + dev eth0")
			l.ip("-n " + h + " route replace default via 10.77.5.1")
			l.eventually("broadcast from the new subnet", func() []string {
				return l.deliveredFrom(1, "10.77.5.2", "10.77.5.255", 6969, 0)
			})
		})
	}

	t.Run("exits for restart when it cannot reopen after dropping privileges", func(t *testing.T) {
		l := newLab(t)
		p := l.relay("relay", base+" --drop-user nobody")
		l.want(1, "before", l.delivered(0, mdnsGroup, 5353, 1))
		l.recreate("r1", 1)
		select {
		case err := <-p.exited:
			if err == nil {
				t.Error("relay exited successfully, want a failure status")
			}
			if !strings.Contains(p.log(), "restart the relay") {
				t.Error("exit reason does not ask for a restart")
			}
		case <-time.After(10 * time.Second):
			t.Error("relay kept running with dead sockets")
		}
	})

	t.Run("relays SSDP unicast replies", func(t *testing.T) {
		l := newLab(t)
		l.relay("relay", base+" --noMDNS --ssdpUnicastAddr 10.77.1.1")
		// Gives the relay host an ARP entry for the searcher, as a router would have.
		l.send("h0", "10.77.0.2", "10.77.0.1", 9, 20, "arp")
		responder := l.start("h1", "respond", "10.77.1.2")
		out, err := l.command("h0", "search", "10.77.0.2").CombinedOutput()
		responder()
		if err != nil || !strings.Contains(string(out), "HTTP/1.1 200") {
			t.Errorf("searcher got no reply: %v: %s", err, out)
		}
	})

	t.Run("drops datagrams larger than the receive buffer", func(t *testing.T) {
		l := newLab(t)
		p := l.relay("relay", base)
		collect := l.start("h1", "receive", mdnsGroup, "5353", "10.77.1.2", "1500")
		l.send("h0", "10.77.0.2", mdnsGroup, 5353, 12000, "huge")
		if got := collect(); len(got) != 0 {
			t.Errorf("oversized datagram delivered: %v", got)
		}
		if !strings.Contains(p.log(), "truncated") {
			t.Error("no warning about the truncated datagram")
		}
	})

	t.Run("ignores other ports on its receive sockets", func(t *testing.T) {
		l := newLab(t)
		p := l.relay("relay", base+" --noMDNS --ssdpUnicastAddr 10.77.1.1")
		// A raw socket on the relay host's own address sees all its UDP traffic.
		l.send("h1", "10.77.1.2", "10.77.1.1", 9, 12000, "other")
		time.Sleep(300 * time.Millisecond)
		if strings.Contains(p.log(), "truncated") {
			t.Error("a datagram for an unrelated port was processed")
		}
	})

	t.Run("relays between two sites", func(t *testing.T) {
		l := newLab(t)
		l.addNS("siteb")
		l.addNS("g0")
		l.link("siteb", "b0", "g0", "10.78.0")
		l.ip(fmt.Sprintf("link add wan netns %s type veth peer name wan netns %s", l.ns("relay"), l.ns("siteb")))
		for ns, addr := range map[string]string{"relay": "192.168.77.1/24", "siteb": "192.168.77.2/24"} {
			l.ip("-n " + l.ns(ns) + " addr add " + addr + " dev wan")
			l.ip("-n " + l.ns(ns) + " link set wan up")
		}
		key := "MULTICAST_RELAY_AES_KEY=end-to-end-test-only"
		l.relay("relay", base+" --listen 192.168.77.2 --remotePort 7000 --noSSDP", key)
		b := l.relay("siteb", "--interfaces b0 --remote 192.168.77.1 --remotePort 7000 --noSSDP", key)
		deadline := time.Now().Add(5 * time.Second)
		for !strings.Contains(b.log(), "established") {
			if time.Now().After(deadline) {
				t.Fatal("sites did not connect")
			}
			time.Sleep(50 * time.Millisecond)
		}
		for _, c := range []struct{ dst, group string }{{mdnsGroup, mdnsGroup}, {"10.77.0.255", "0.0.0.0"}} {
			port := "5353"
			if c.group == "0.0.0.0" {
				port = "6969"
			}
			collect := l.start("g0", "receive", c.group, port, "10.78.0.2", "1500")
			l.send("h0", "10.77.0.2", c.dst, map[string]int{"5353": 5353, "6969": 6969}[port], 150, "wan"+port)
			l.want(1, "far site, "+c.dst, collect())
		}
	})
}

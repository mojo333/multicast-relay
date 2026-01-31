// Package relay implements the core multicast/broadcast packet relay engine.
package relay

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mojo333/multicast-relay/internal/cipher"
	"github.com/mojo333/multicast-relay/internal/logger"

	"golang.org/x/sys/unix"
)

// Protocol constants matching the Python version.
const (
	MulticastMin    = "224.0.0.0"
	MulticastMax    = "239.255.255.255"
	BroadcastAddr   = "255.255.255.255"
	SSDPMcastAddr   = "239.255.255.250"
	SSDPMcastPort   = 1900
	SSDPUnicastPort = 1901
	MDNSMcastAddr   = "224.0.0.251"
	MDNSMcastPort   = 5353

	udpMaxLength       = 1458
	maxRecentChecksums = 256

	// ethPAllBE is ETH_P_ALL in network byte order (big-endian).
	ethPAllBE = (unix.ETH_P_ALL>>8)&0xff | (unix.ETH_P_ALL&0xff)<<8
)

const (
	// maxPacketSize is the maximum expected packet size for pooled buffers.
	maxPacketSize = 10240
)

var (
	magicBytes = [4]byte{'M', 'R', 'L', 'Y'}
	zeroMAC    = net.HardwareAddr{0, 0, 0, 0, 0, 0}

	ssdpSearchRe = regexp.MustCompile(`M-SEARCH|NOTIFY`)

	// packetPool provides reusable byte buffers for packet processing.
	packetPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 0, maxPacketSize)
			return &b
		},
	}
)

// getBuffer retrieves a buffer from the pool and sets its length to n.
func getBuffer(n int) *[]byte {
	bp := packetPool.Get().(*[]byte)
	b := *bp
	if cap(b) < n {
		b = make([]byte, n, n*2)
	} else {
		b = b[:n]
	}
	*bp = b
	return bp
}

// putBuffer returns a buffer to the pool.
func putBuffer(bp *[]byte) {
	packetPool.Put(bp)
}

// ssdpSearchSource tracks the most recent SSDP search source for unicast reply routing.
type ssdpSearchSource struct {
	addr string
	port uint16
	set  bool
}

// parsedFilter is a pre-parsed ifFilter entry.
type parsedFilter struct {
	prefix netip.Prefix
	ifaces []string
}

// RelayAddr stores a multicast/broadcast address and port pair.
type RelayAddr struct {
	Addr string
	Port int
}

// Transmitter holds the per-interface transmitter socket and metadata.
type Transmitter struct {
	Relay     RelayAddr
	Interface string
	Addr      string
	MAC       net.HardwareAddr
	Netmask   string
	Broadcast string
	Socket    int // raw AF_PACKET socket fd
	Service   string
}

// Receiver wraps a raw receive socket fd.
type Receiver struct {
	fd int
}

// RemoteAddr holds state for a remote relay connection target.
type RemoteAddr struct {
	Addr           string
	Conn           net.Conn
	Connecting     bool
	ConnectFailure time.Time
}

// Config holds all configuration for the PacketRelay.
type Config struct {
	Interfaces           []string
	NoTransmitInterfaces []string
	IfFilter             string
	WaitForIP            bool
	TTL                  int
	OneInterface         bool
	AllowNonEther        bool
	SSDPUnicastAddr      string
	MDNSForceUnicast     bool
	Masquerade           []string
	Listen               []string
	Remote               []string
	RemotePort           int
	RemoteRetry          int
	NoRemoteRelay        bool
	AESKey               string
	Logger               *logger.Logger
}

// PacketRelay is the main relay engine.
type PacketRelay struct {
	interfaces           []string
	noTransmitInterfaces map[string]bool
	parsedFilters        []parsedFilter
	ssdpUnicastAddr      string
	mdnsForceUnicast     bool
	wait                 bool
	ttl                  int
	oneInterface         bool
	allowNonEther        bool
	masquerade           map[string]bool

	logger *logger.Logger

	transmitters []Transmitter
	receivers    []Receiver
	etherAddrs   map[string]net.HardwareAddr
	etherType    [2]byte

	// Ring buffer for duplicate detection.
	// Only accessed from the single-threaded main loop (Loop -> processPacket).
	recentChecksums [maxRecentChecksums]uint16
	checksumIdx     int
	checksumCount   int

	listenAddr        []string
	listener          *net.TCPListener
	acceptCh          chan net.Conn
	remoteAddrs       []*RemoteAddr
	remotePort        int
	remoteRetry       int
	noRemoteRelay     bool
	aes               *cipher.Cipher
	remoteConnections []net.Conn

	// Pre-allocated poll structures rebuilt when receivers change.
	pollFds   []unix.PollFd
	pollDirty bool
}

// New creates and initializes a new PacketRelay.
func New(cfg Config) (*PacketRelay, error) {
	noTx := make(map[string]bool, len(cfg.NoTransmitInterfaces))
	for _, nt := range cfg.NoTransmitInterfaces {
		noTx[nt] = true
	}
	masq := make(map[string]bool, len(cfg.Masquerade))
	for _, m := range cfg.Masquerade {
		masq[m] = true
	}

	pr := &PacketRelay{
		interfaces:           cfg.Interfaces,
		noTransmitInterfaces: noTx,
		ssdpUnicastAddr:      cfg.SSDPUnicastAddr,
		mdnsForceUnicast:     cfg.MDNSForceUnicast,
		wait:                 cfg.WaitForIP,
		ttl:                  cfg.TTL,
		oneInterface:         cfg.OneInterface,
		allowNonEther:        cfg.AllowNonEther,
		masquerade:           masq,
		logger:               cfg.Logger,
		etherAddrs:           make(map[string]net.HardwareAddr),
		etherType:  [2]byte{0x08, 0x00}, // IPv4
		listenAddr: cfg.Listen,
		remotePort:           cfg.RemotePort,
		remoteRetry:          cfg.RemoteRetry,
		noRemoteRelay:        cfg.NoRemoteRelay,
		aes:                  cipher.New(cfg.AESKey),
		pollDirty:            true,
	}

	if cfg.IfFilter != "" {
		rawFilters, err := parseIfFilterFile(cfg.IfFilter)
		if err != nil {
			return nil, err
		}
		pr.parsedFilters = rawFilters
	}

	if cfg.Remote != nil {
		for _, addr := range cfg.Remote {
			pr.remoteAddrs = append(pr.remoteAddrs, &RemoteAddr{Addr: addr})
		}
	}

	// Set up listen socket if in server mode
	if len(cfg.Listen) > 0 {
		laddr := &net.TCPAddr{Port: pr.remotePort}
		ln, err := net.ListenTCP("tcp4", laddr)
		if err != nil {
			return nil, fmt.Errorf("cannot listen on port %d: %w", pr.remotePort, err)
		}
		pr.listener = ln
		pr.acceptCh = make(chan net.Conn, 8)
		go pr.acceptLoop()
	} else if len(pr.remoteAddrs) > 0 {
		pr.connectRemotes()
	}

	return pr, nil
}

// parseIfFilterFile reads and pre-parses the ifFilter JSON file into netip.Prefix entries.
func parseIfFilterFile(path string) ([]parsedFilter, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read ifFilter file %s: %w", path, err)
	}
	var raw map[string][]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("cannot parse ifFilter JSON: %w", err)
	}
	var filters []parsedFilter
	for netStr, ifaces := range raw {
		// If no CIDR suffix, default to /32
		if !strings.Contains(netStr, "/") {
			netStr += "/32"
		}
		prefix, err := netip.ParsePrefix(netStr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR in ifFilter key %q: %w", netStr, err)
		}
		filters = append(filters, parsedFilter{
			prefix: prefix,
			ifaces: ifaces,
		})
	}
	return filters, nil
}

// AddListener sets up receive and transmit sockets for a relay address.
func (pr *PacketRelay) AddListener(addr string, port int, service string) error {
	if IsBroadcast(addr) {
		pr.etherAddrs[addr] = BroadcastIPToMAC()
	} else if IsMulticast(addr) {
		pr.etherAddrs[addr] = MulticastIPToMAC(addr)
	} else {
		pr.etherAddrs[addr] = nil
	}

	var multicastRxFd int = -1

	if IsMulticast(addr) {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_UDP)
		if err != nil {
			return fmt.Errorf("cannot create multicast receive socket: %w", err)
		}
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			unix.Close(fd)
			return fmt.Errorf("cannot set SO_REUSEADDR: %w", err)
		}
		multicastRxFd = fd
	}

	for _, iface := range pr.interfaces {
		ifInfo, err := pr.getInterface(iface)
		if err != nil {
			return err
		}

		if IsBroadcast(addr) {
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_UDP)
			if err != nil {
				return fmt.Errorf("cannot create broadcast receive socket: %w", err)
			}
			if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
				unix.Close(fd)
				return fmt.Errorf("cannot set SO_REUSEADDR: %w", err)
			}
			if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1); err != nil {
				unix.Close(fd)
				return fmt.Errorf("cannot set SO_BROADCAST: %w", err)
			}

			bcastIP := net.ParseIP(ifInfo.Broadcast).To4()
			sa := &unix.SockaddrInet4{Port: port}
			copy(sa.Addr[:], bcastIP)
			if err := unix.Bind(fd, sa); err != nil {
				unix.Close(fd)
				return fmt.Errorf("cannot bind broadcast socket to %s:%d: %w", ifInfo.Broadcast, port, err)
			}
			pr.receivers = append(pr.receivers, Receiver{fd: fd})

		} else if IsMulticast(addr) {
			mcastIP := net.ParseIP(addr).To4()
			ifIP := net.ParseIP(ifInfo.IP).To4()
			mreq := &unix.IPMreq{}
			copy(mreq.Multiaddr[:], mcastIP)
			copy(mreq.Interface[:], ifIP)
			if err := unix.SetsockoptIPMreq(multicastRxFd, unix.SOL_IP, unix.IP_ADD_MEMBERSHIP, mreq); err != nil {
				return fmt.Errorf("cannot join multicast group %s on %s: %w", addr, ifInfo.Name, err)
			}
		}

		// Create transmitter for this interface (unless in noTransmitInterfaces)
		if !pr.noTransmitInterfaces[iface] {
			txFd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, ethPAllBE)
			if err != nil {
				return fmt.Errorf("cannot create transmit socket for %s: %w", ifInfo.Name, err)
			}

			ifIndex, err := interfaceIndex(ifInfo.Name)
			if err != nil {
				unix.Close(txFd)
				return fmt.Errorf("cannot get interface index for %s: %w", ifInfo.Name, err)
			}

			sa := &unix.SockaddrLinklayer{
				Protocol: uint16(ethPAllBE),
				Ifindex:  ifIndex,
			}
			if err := unix.Bind(txFd, sa); err != nil {
				unix.Close(txFd)
				return fmt.Errorf("cannot bind transmit socket to %s: %w", ifInfo.Name, err)
			}

			listenIP := addr
			if IsBroadcast(addr) {
				listenIP = ifInfo.Broadcast
			}

			pr.transmitters = append(pr.transmitters, Transmitter{
				Relay:     RelayAddr{Addr: listenIP, Port: port},
				Interface: ifInfo.Name,
				Addr:      ifInfo.IP,
				MAC:       ifInfo.MAC,
				Netmask:   ifInfo.Netmask,
				Broadcast: ifInfo.Broadcast,
				Socket:    txFd,
				Service:   service,
			})
		}
	}

	if IsMulticast(addr) {
		mcastIP := net.ParseIP(addr).To4()
		sa := &unix.SockaddrInet4{Port: port}
		copy(sa.Addr[:], mcastIP)
		if err := unix.Bind(multicastRxFd, sa); err != nil {
			unix.Close(multicastRxFd)
			return fmt.Errorf("cannot bind multicast socket to %s:%d: %w", addr, port, err)
		}
		pr.receivers = append(pr.receivers, Receiver{fd: multicastRxFd})
	}

	pr.pollDirty = true
	return nil
}

// rebuildPollFds rebuilds the pre-allocated poll fd set.
func (pr *PacketRelay) rebuildPollFds() {
	pr.pollFds = make([]unix.PollFd, 0, len(pr.receivers))

	for _, rx := range pr.receivers {
		pr.pollFds = append(pr.pollFds, unix.PollFd{Fd: int32(rx.fd), Events: unix.POLLIN})
	}

	pr.pollDirty = false
}

// Loop runs the main packet relay event loop.
func (pr *PacketRelay) Loop() error {
	var ssdpSrc ssdpSearchSource

	buf := make([]byte, 10240)

	for {
		if len(pr.remoteAddrs) > 0 {
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
					pr.logger.Info("REMOTE: Accepted connection from %s", conn.RemoteAddr())
				default:
					break drainAccept
				}
			}
		}

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
				pr.logger.Info("Error receiving packet: %s", err)
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

			pr.processPacket(*dataBp, senderAddr, "local", &ssdpSrc)
			putBuffer(dataBp)
		}
	}
}

// processPacket processes an incoming packet and relays it to other interfaces.
func (pr *PacketRelay) processPacket(data []byte, senderAddr string, receivingInterface string, ssdpSrc *ssdpSearchSource) {
	if len(data) < 28 { // min IP header + UDP header
		return
	}

	// Forward to remote connections
	remotes := pr.remoteSockets()
	if len(remotes) > 0 && !(receivingInterface == "remote" && pr.noRemoteRelay) {
		senderIP := net.ParseIP(senderAddr).To4()
		if senderIP != nil {
			// Build packet without mutating magicBytes
			packet := make([]byte, 0, len(magicBytes)+4+len(data))
			packet = append(packet, magicBytes[:]...)
			packet = append(packet, senderIP...)
			packet = append(packet, data...)

			encrypted, err := pr.aes.Encrypt(packet)
			if err == nil {
				payload := make([]byte, 2+len(encrypted))
				binary.BigEndian.PutUint16(payload[0:2], uint16(len(encrypted)))
				copy(payload[2:], encrypted)

				for _, conn := range remotes {
					if _, err := conn.Write(payload); err != nil {
						pr.logger.Info("REMOTE: Write error: %s", err)
					}
				}
			}
		}
	}

	// Extract TTL
	ttl := data[8]
	if pr.ttl > 0 {
		data[8] = byte(pr.ttl)
	}

	// Duplicate detection via IP checksum
	ipChecksum := binary.BigEndian.Uint16(data[10:12])
	if pr.isDuplicate(ipChecksum) {
		return
	}

	srcAddr := AddrFrom4Bytes(data[12:16]).String()
	dstAddr := AddrFrom4Bytes(data[16:20]).String()

	// IP header length
	ipHeaderLength := int(data[0]&0x0f) * 4
	if ipHeaderLength < 20 || ipHeaderLength > len(data)-8 {
		return
	}
	srcPort := binary.BigEndian.Uint16(data[ipHeaderLength : ipHeaderLength+2])
	dstPort := binary.BigEndian.Uint16(data[ipHeaderLength+2 : ipHeaderLength+4])

	origSrcAddr := srcAddr
	origSrcPort := srcPort
	origDstAddr := dstAddr
	origDstPort := dstPort

	var destMac net.HardwareAddr

	// mDNS unicast forcing
	if pr.mdnsForceUnicast && dstAddr == MDNSMcastAddr && dstPort == MDNSMcastPort {
		data = MdnsSetUnicastBit(data, ipHeaderLength)
	}

	// SSDP M-SEARCH / NOTIFY interception
	if pr.ssdpUnicastAddr != "" && dstAddr == SSDPMcastAddr && dstPort == SSDPMcastPort && ssdpSearchRe.Match(data) {
		ssdpSrc.addr = srcAddr
		ssdpSrc.port = srcPort
		ssdpSrc.set = true
		pr.logger.Info("Last SSDP search source: %s:%d", srcAddr, srcPort)

		srcAddr = pr.ssdpUnicastAddr
		srcPort = SSDPUnicastPort
		data = ModifyUDPPacket(data, ipHeaderLength, srcAddr, srcPort, "", 0)
	} else if pr.ssdpUnicastAddr != "" && origDstAddr == pr.ssdpUnicastAddr && origDstPort == SSDPUnicastPort {
		if !ssdpSrc.set {
			return
		}
		dstAddr = ssdpSrc.addr
		dstPort = ssdpSrc.port
		pr.logger.Info("Received SSDP Unicast - received from %s:%d on %s:%d, need to relay to %s:%d",
			origSrcAddr, origSrcPort, origDstAddr, origDstPort, dstAddr, dstPort)

		data = ModifyUDPPacket(data, ipHeaderLength, "", 0, dstAddr, dstPort)

		macStr, err := UnicastIPToMAC(dstAddr, "")
		if err != nil || macStr == "" {
			pr.logger.Info("Could not resolve MAC for %s", dstAddr)
			return
		}
		destMac, err = net.ParseMAC(macStr)
		if err != nil {
			pr.logger.Info("Could not parse MAC %s: %s", macStr, err)
			return
		}
	}

	// Determine receiving interface
	broadcastPacket := false
	if receivingInterface == "local" {
		for _, tx := range pr.transmitters {
			if origDstAddr == tx.Relay.Addr && int(origDstPort) == tx.Relay.Port &&
				OnNetwork(senderAddr, tx.Addr, tx.Netmask) {
				receivingInterface = tx.Interface
				broadcastPacket = (origDstAddr == tx.Broadcast)
			}
		}
	}

	// Relay to all other interfaces
	for i := range pr.transmitters {
		tx := &pr.transmitters[i]

		if receivingInterface == tx.Interface {
			continue
		}

		// Apply ifFilter
		if !pr.isAllowedByFilter(srcAddr, tx.Interface) {
			continue
		}

		localDstAddr := dstAddr
		localDestMac := destMac
		localOrigDstAddr := origDstAddr

		if broadcastPacket {
			localDstAddr = tx.Broadcast
			localDestMac = pr.etherAddrs[BroadcastAddr]
			localOrigDstAddr = tx.Broadcast
		}

		if localOrigDstAddr == tx.Relay.Addr && int(origDstPort) == tx.Relay.Port &&
			(pr.oneInterface || !OnNetwork(senderAddr, tx.Addr, tx.Netmask)) {

			if localDestMac == nil {
				localDestMac = pr.etherAddrs[localDstAddr]
			}
			if localDestMac == nil {
				continue
			}

			txBp := getBuffer(len(data))
			txData := *txBp
			copy(txData, data)

			isMasq := pr.masquerade[tx.Interface]
			if isMasq {
				copy(txData[12:16], net.ParseIP(tx.Addr).To4())
			}

			servicePrefix := ""
			if tx.Service != "" {
				servicePrefix = fmt.Sprintf("[%s] ", tx.Service)
			}
			action := "Relayed"
			if isMasq {
				action = "Masqueraded"
			}
			plural := "s"
			if len(txData) == 1 {
				plural = ""
			}
			pr.logger.Info("%s%s %d byte%s from %s:%d on %s [ttl %d] to %s:%d via %s/%s",
				servicePrefix, action, len(txData), plural,
				srcAddr, srcPort, receivingInterface, ttl,
				localDstAddr, dstPort, tx.Interface, tx.Addr)

			if err := pr.transmitPacket(tx, localDestMac, ipHeaderLength, txData); err != nil {
				// Try to recover if ENXIO (device not configured)
				if isENXIO(err) {
					pr.recoverTransmitter(tx, localDestMac, ipHeaderLength, txData)
				} else {
					pr.logger.Info("Error sending packet: %s", err)
				}
			}
			putBuffer(txBp)
		}
	}
}

// isDuplicate checks whether this checksum was recently seen.
// Not safe for concurrent use — only call from the main loop goroutine.
func (pr *PacketRelay) isDuplicate(checksum uint16) bool {
	n := pr.checksumCount
	if n > maxRecentChecksums {
		n = maxRecentChecksums
	}
	for i := 0; i < n; i++ {
		if pr.recentChecksums[i] == checksum {
			return true
		}
	}
	return false
}

// addChecksum records a checksum in the ring buffer.
// Not safe for concurrent use — only call from the main loop goroutine.
func (pr *PacketRelay) addChecksum(checksum uint16) {
	pr.recentChecksums[pr.checksumIdx] = checksum
	pr.checksumIdx = (pr.checksumIdx + 1) % maxRecentChecksums
	if pr.checksumCount < maxRecentChecksums {
		pr.checksumCount++
	}
}

// isAllowedByFilter checks the pre-parsed ifFilter rules.
func (pr *PacketRelay) isAllowedByFilter(srcAddr, txInterface string) bool {
	for _, f := range pr.parsedFilters {
		if OnNetworkPrefix(srcAddr, f.prefix) {
			for _, iface := range f.ifaces {
				if iface == txInterface {
					return true
				}
			}
			return false
		}
	}
	return true
}

// recoverTransmitter attempts to re-create the transmit socket after ENXIO.
func (pr *PacketRelay) recoverTransmitter(tx *Transmitter, destMac net.HardwareAddr, ipHeaderLength int, data []byte) {
	pr.logger.Info("Attempting to recover interface %s", tx.Interface)
	ifInfo, err := pr.getInterface(tx.Interface)
	if err != nil {
		pr.logger.Info("Recovery failed for %s: %s", tx.Interface, err)
		return
	}
	newFd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, ethPAllBE)
	if err != nil {
		pr.logger.Info("Recovery socket creation failed for %s: %s", tx.Interface, err)
		return
	}
	ifIdx, err := interfaceIndex(ifInfo.Name)
	if err != nil {
		unix.Close(newFd)
		pr.logger.Info("Recovery interface index failed for %s: %s", tx.Interface, err)
		return
	}
	sa := &unix.SockaddrLinklayer{
		Protocol: uint16(ethPAllBE),
		Ifindex:  ifIdx,
	}
	if err := unix.Bind(newFd, sa); err != nil {
		unix.Close(newFd)
		pr.logger.Info("Recovery bind failed for %s: %s", tx.Interface, err)
		return
	}
	unix.Close(tx.Socket)
	tx.Socket = newFd
	tx.MAC = ifInfo.MAC
	tx.Netmask = ifInfo.Netmask
	tx.Addr = ifInfo.IP
	if err := pr.transmitPacket(tx, destMac, ipHeaderLength, data); err != nil {
		pr.logger.Info("Recovery retransmit failed for %s: %s", tx.Interface, err)
	}
}

// transmitPacket builds ethernet frames and sends a packet via a transmitter socket.
// Uses a pooled scratch buffer to avoid per-fragment heap allocations.
func (pr *PacketRelay) transmitPacket(tx *Transmitter, destMac net.HardwareAddr, ipHeaderLength int, data []byte) error {
	ipHeader := data[:ipHeaderLength]
	udpHeader := data[ipHeaderLength : ipHeaderLength+8]
	payload := data[ipHeaderLength+8:]

	dontFragment := (data[6] & 0x40) >> 6

	udpHeader = ComputeUDPChecksum(ipHeader, udpHeader, payload)

	hasEther := !bytes.Equal(tx.MAC, zeroMAC)

	// Get a scratch buffer large enough for the largest frame: 14 (ether) + full packet
	maxFrameSize := 14 + len(data)
	scratchBp := getBuffer(maxFrameSize)
	defer putBuffer(scratchBp)
	scratch := *scratchBp

	for boundary := 0; boundary < len(payload); boundary += udpMaxLength {
		end := boundary + udpMaxLength
		if end > len(payload) {
			end = len(payload)
		}
		dataFragment := payload[boundary:end]
		totalLength := ipHeaderLength + 8 + len(dataFragment)
		moreFragments := end < len(payload)

		flagsOffset := uint16(boundary & 0x1fff)
		if moreFragments {
			flagsOffset |= 0x2000
		} else if dontFragment != 0 {
			flagsOffset |= 0x4000
		}

		// Build the IP packet into the scratch buffer (after ether header space)
		etherOff := 0
		if hasEther {
			etherOff = 14
		}

		// Copy IP header, modify total length and flags/offset
		copy(scratch[etherOff:], ipHeader)
		binary.BigEndian.PutUint16(scratch[etherOff+2:etherOff+4], uint16(totalLength))
		binary.BigEndian.PutUint16(scratch[etherOff+6:etherOff+8], flagsOffset)

		// Append UDP header and data fragment
		copy(scratch[etherOff+ipHeaderLength:], udpHeader)
		copy(scratch[etherOff+ipHeaderLength+8:], dataFragment)

		ipPacket := scratch[etherOff : etherOff+totalLength]
		ComputeIPChecksum(ipPacket, ipHeaderLength)

		// Track checksum for duplicate detection
		cs := binary.BigEndian.Uint16(ipPacket[10:12])
		pr.addChecksum(cs)

		var frame []byte
		if hasEther {
			// Prepend ethernet header: destMac + srcMac + etherType
			copy(scratch[0:6], destMac)
			copy(scratch[6:12], tx.MAC)
			copy(scratch[12:14], pr.etherType[:])
			frame = scratch[:14+totalLength]
		} else {
			frame = ipPacket
		}

		if err := unix.Send(tx.Socket, frame, 0); err != nil {
			return err
		}
	}

	return nil
}

// InterfaceResult holds resolved interface information.
type InterfaceResult struct {
	Name      string
	MAC       net.HardwareAddr
	IP        string
	Netmask   string
	Broadcast string
}

// resolveInterface does a single pass over all system interfaces to find one
// matching by name, IPv4 address, or CIDR block. This replaces the old
// netifaces package which required up to 3 separate full enumerations.
func resolveInterface(spec string) (*InterfaceResult, error) {
	// Determine if spec is a CIDR prefix, an IP address, or a name.
	specPrefix, cidrErr := netip.ParsePrefix(spec)
	specAddr, addrErr := netip.ParseAddr(spec)
	isCIDR := cidrErr == nil
	isIP := !isCIDR && addrErr == nil

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}

	for _, iface := range ifaces {
		nameMatch := (iface.Name == spec)

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue
			}

			ifAddr := AddrFrom4Bytes(ip4)

			matched := nameMatch
			if !matched && isIP && ifAddr == specAddr {
				matched = true
			}
			if !matched && isCIDR && specPrefix.Contains(ifAddr) {
				matched = true
			}
			if !matched {
				continue
			}

			mask := ipnet.Mask
			if len(mask) == 16 {
				mask = mask[12:]
			}
			ipInt := binary.BigEndian.Uint32(ip4)
			maskInt := binary.BigEndian.Uint32(mask)
			bcastInt := ipInt | ^maskInt
			var bcastBytes [4]byte
			binary.BigEndian.PutUint32(bcastBytes[:], bcastInt)

			return &InterfaceResult{
				Name:      iface.Name,
				MAC:       iface.HardwareAddr,
				IP:        ifAddr.String(),
				Netmask:   fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3]),
				Broadcast: netip.AddrFrom4(bcastBytes).String(),
			}, nil
		}
	}

	return nil, fmt.Errorf("interface %s not found", spec)
}

// getInterface resolves an interface spec and optionally waits for an IPv4 address.
func (pr *PacketRelay) getInterface(iface string) (*InterfaceResult, error) {
	result, err := resolveInterface(iface)
	if err != nil {
		return nil, err
	}

	// Wait for IPv4 address if configured
	if pr.wait && result.IP == "" {
		for {
			pr.logger.Info("Waiting for IPv4 address on %s", result.Name)
			time.Sleep(time.Second)
			result, err = resolveInterface(result.Name)
			if err != nil {
				return nil, err
			}
			if result.IP != "" {
				break
			}
		}
	}

	if result.IP == "" {
		return nil, fmt.Errorf("interface %s does not have an IPv4 address assigned", iface)
	}

	if len(result.MAC) == 0 {
		if pr.allowNonEther {
			result.MAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}
		} else {
			return nil, fmt.Errorf("unable to detect MAC address for interface %s", result.Name)
		}
	}

	return result, nil
}

// remoteSockets collects all active remote relay connections.
func (pr *PacketRelay) remoteSockets() []net.Conn {
	var conns []net.Conn
	conns = append(conns, pr.remoteConnections...)
	for _, ra := range pr.remoteAddrs {
		if ra.Conn != nil {
			conns = append(conns, ra.Conn)
		}
	}
	return conns
}

// connectRemotes establishes TCP connections to configured remote relays.
func (pr *PacketRelay) connectRemotes() {
	for _, remote := range pr.remoteAddrs {
		if remote.Conn != nil {
			continue
		}
		if !remote.ConnectFailure.IsZero() && time.Since(remote.ConnectFailure) < time.Duration(pr.remoteRetry)*time.Second {
			continue
		}
		pr.logger.Info("REMOTE: Connecting to remote %s", remote.Addr)
		remote.Connecting = true
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", remote.Addr, pr.remotePort), 5*time.Second)
		if err != nil {
			remote.Connecting = false
			remote.ConnectFailure = time.Now()
			pr.logger.Info("REMOTE: Failed to connect to %s: %s", remote.Addr, err)
			continue
		}
		remote.Conn = conn
		remote.Connecting = false
		pr.logger.Info("REMOTE: Connection to %s established", remote.Addr)
	}
}

// removeConnection removes a remote connection from the active set.
func (pr *PacketRelay) removeConnection(conn net.Conn) {
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
			pr.logger.Info("Refusing connection from %s - not in allowed list", remoteIP)
			conn.Close()
			continue
		}

		pr.acceptCh <- conn
	}
}

// interfaceIndex returns the OS interface index for a named interface.
func interfaceIndex(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return iface.Index, nil
}

// isENXIO checks if an error is the ENXIO errno.
func isENXIO(err error) bool {
	return err == unix.ENXIO
}

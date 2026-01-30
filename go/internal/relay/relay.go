// Package relay implements the core multicast/broadcast packet relay engine.
package relay

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
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
)

var (
	magicBytes = [4]byte{'M', 'R', 'L', 'Y'}
	zeroMAC    = net.HardwareAddr{0, 0, 0, 0, 0, 0}

	// Pre-compiled regexes for hot paths.
	ssdpSearchRe = regexp.MustCompile(`M-SEARCH|NOTIFY`)
	ipAddrRe     = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
	cidrRe       = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+/\d+$`)
)

// ssdpSearchSource tracks the most recent SSDP search source for unicast reply routing.
type ssdpSearchSource struct {
	addr string
	port uint16
	set  bool
}

// parsedFilter is a pre-parsed ifFilter entry.
type parsedFilter struct {
	network string
	netmask string
	ifaces  []string
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
	recentChecksums [maxRecentChecksums]uint16
	checksumIdx     int
	checksumCount   int
	mu              sync.Mutex

	listenAddr        []string
	listenFd          int
	remoteAddrs       []*RemoteAddr
	remotePort        int
	remoteRetry       int
	noRemoteRelay     bool
	aes               *cipher.Cipher
	remoteConnections []net.Conn

	// Pre-allocated poll structures rebuilt when receivers change.
	pollFds []unix.PollFd
	fdRoles []string // parallel to pollFds: "listen" or "receiver"
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
		etherType:            [2]byte{0x08, 0x00}, // IPv4
		listenFd:             -1,
		listenAddr:           cfg.Listen,
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
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		if err != nil {
			return nil, fmt.Errorf("cannot create listen socket: %w", err)
		}
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("cannot set SO_REUSEADDR: %w", err)
		}

		sa := &unix.SockaddrInet4{Port: pr.remotePort}
		if err := unix.Bind(fd, sa); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("cannot bind listen socket: %w", err)
		}
		if err := unix.Listen(fd, 5); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("cannot listen: %w", err)
		}
		pr.listenFd = fd
	} else if len(pr.remoteAddrs) > 0 {
		pr.connectRemotes()
	}

	return pr, nil
}

// parseIfFilterFile reads and pre-parses the ifFilter JSON file into network/netmask pairs.
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
		parts := strings.SplitN(netStr, "/", 2)
		network := parts[0]
		bits := 32
		if len(parts) == 2 {
			b, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR bits in ifFilter key %q: %w", netStr, err)
			}
			bits = b
		}
		filters = append(filters, parsedFilter{
			network: network,
			netmask: CIDRToNetmask(bits),
			ifaces:  ifaces,
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
			txFd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
			if err != nil {
				return fmt.Errorf("cannot create transmit socket for %s: %w", ifInfo.Name, err)
			}

			ifIndex, err := interfaceIndex(ifInfo.Name)
			if err != nil {
				unix.Close(txFd)
				return fmt.Errorf("cannot get interface index for %s: %w", ifInfo.Name, err)
			}

			sa := &unix.SockaddrLinklayer{
				Protocol: htons(unix.ETH_P_ALL),
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
	count := len(pr.receivers)
	if pr.listenFd >= 0 {
		count++
	}

	pr.pollFds = make([]unix.PollFd, 0, count)
	pr.fdRoles = make([]string, 0, count)

	if pr.listenFd >= 0 {
		pr.pollFds = append(pr.pollFds, unix.PollFd{Fd: int32(pr.listenFd), Events: unix.POLLIN})
		pr.fdRoles = append(pr.fdRoles, "listen")
	}

	for _, rx := range pr.receivers {
		pr.pollFds = append(pr.pollFds, unix.PollFd{Fd: int32(rx.fd), Events: unix.POLLIN})
		pr.fdRoles = append(pr.fdRoles, "receiver")
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

		for i, pfd := range pr.pollFds {
			if pfd.Revents&unix.POLLIN == 0 {
				continue
			}

			if pr.fdRoles[i] == "listen" {
				pr.handleListenAccept(int(pfd.Fd))
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

			data := make([]byte, nread)
			copy(data, buf[:nread])

			sa, ok := from.(*unix.SockaddrInet4)
			if !ok {
				continue
			}
			senderAddr := net.IP(sa.Addr[:]).String()

			pr.processPacket(data, senderAddr, "local", &ssdpSrc)
		}
	}
}

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

	srcAddr := net.IP(data[12:16]).String()
	dstAddr := net.IP(data[16:20]).String()

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

			txData := make([]byte, len(data))
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
		}
	}
}

// isDuplicate checks whether this checksum was recently seen.
func (pr *PacketRelay) isDuplicate(checksum uint16) bool {
	pr.mu.Lock()
	defer pr.mu.Unlock()
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
func (pr *PacketRelay) addChecksum(checksum uint16) {
	pr.mu.Lock()
	pr.recentChecksums[pr.checksumIdx] = checksum
	pr.checksumIdx = (pr.checksumIdx + 1) % maxRecentChecksums
	if pr.checksumCount < maxRecentChecksums {
		pr.checksumCount++
	}
	pr.mu.Unlock()
}

// isAllowedByFilter checks the pre-parsed ifFilter rules.
func (pr *PacketRelay) isAllowedByFilter(srcAddr, txInterface string) bool {
	for _, f := range pr.parsedFilters {
		if OnNetwork(srcAddr, f.network, f.netmask) {
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
	newFd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
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
		Protocol: htons(unix.ETH_P_ALL),
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

func (pr *PacketRelay) transmitPacket(tx *Transmitter, destMac net.HardwareAddr, ipHeaderLength int, data []byte) error {
	ipHeader := data[:ipHeaderLength]
	udpHeader := data[ipHeaderLength : ipHeaderLength+8]
	payload := data[ipHeaderLength+8:]

	dontFragment := (data[6] & 0x40) >> 6

	udpHeader = ComputeUDPChecksum(ipHeader, udpHeader, payload)

	for boundary := 0; boundary < len(payload); boundary += udpMaxLength {
		end := boundary + udpMaxLength
		if end > len(payload) {
			end = len(payload)
		}
		dataFragment := payload[boundary:end]
		totalLength := len(ipHeader) + len(udpHeader) + len(dataFragment)
		moreFragments := end < len(payload)

		flagsOffset := uint16(boundary & 0x1fff)
		if moreFragments {
			flagsOffset |= 0x2000
		} else if dontFragment != 0 {
			flagsOffset |= 0x4000
		}

		// Update total length and flags/offset
		fragIPHeader := make([]byte, len(ipHeader))
		copy(fragIPHeader, ipHeader)
		binary.BigEndian.PutUint16(fragIPHeader[2:4], uint16(totalLength))
		binary.BigEndian.PutUint16(fragIPHeader[6:8], flagsOffset)

		ipPacket := make([]byte, 0, len(fragIPHeader)+len(udpHeader)+len(dataFragment))
		ipPacket = append(ipPacket, fragIPHeader...)
		ipPacket = append(ipPacket, udpHeader...)
		ipPacket = append(ipPacket, dataFragment...)

		ipPacket = ComputeIPChecksum(ipPacket, ipHeaderLength)

		// Track checksum for duplicate detection
		cs := binary.BigEndian.Uint16(ipPacket[10:12])
		pr.addChecksum(cs)

		var packet []byte
		if !bytes.Equal(tx.MAC, zeroMAC) {
			// Prepend ethernet header: destMac + srcMac + etherType
			packet = make([]byte, 0, 14+len(ipPacket))
			packet = append(packet, destMac...)
			packet = append(packet, tx.MAC...)
			packet = append(packet, pr.etherType[:]...)
			packet = append(packet, ipPacket...)
		} else {
			packet = ipPacket
		}

		if err := unix.Send(tx.Socket, packet, 0); err != nil {
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
	isCIDR := cidrRe.MatchString(spec)
	isIP := !isCIDR && ipAddrRe.MatchString(spec)

	var cidrNet *net.IPNet
	if isCIDR {
		var err error
		_, cidrNet, err = net.ParseCIDR(spec)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %s: %w", spec, err)
		}
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}

	for _, iface := range ifaces {
		// Name match: quick reject
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

			matched := nameMatch
			if !matched && isIP && ip4.String() == spec {
				matched = true
			}
			if !matched && isCIDR && cidrNet.Contains(ip4) {
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
			bcast := make(net.IP, 4)
			binary.BigEndian.PutUint32(bcast, bcastInt)

			return &InterfaceResult{
				Name:      iface.Name,
				MAC:       iface.HardwareAddr,
				IP:        ip4.String(),
				Netmask:   fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3]),
				Broadcast: bcast.String(),
			}, nil
		}
	}

	return nil, fmt.Errorf("interface %s not found", spec)
}

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

func (pr *PacketRelay) handleListenAccept(fd int) {
	nfd, sa, err := unix.Accept(fd)
	if err != nil {
		return
	}

	var remoteIP string
	if sa4, ok := sa.(*unix.SockaddrInet4); ok {
		remoteIP = net.IP(sa4.Addr[:]).String()
	}

	allowed := false
	for _, addr := range pr.listenAddr {
		if addr == remoteIP {
			allowed = true
			break
		}
	}

	if !allowed {
		pr.logger.Info("Refusing connection from %s - not in allowed list", remoteIP)
		unix.Close(nfd)
		return
	}

	file := os.NewFile(uintptr(nfd), "remote")
	conn, err := net.FileConn(file)
	file.Close()
	if err != nil {
		unix.Close(nfd)
		return
	}

	pr.remoteConnections = append(pr.remoteConnections, conn)
	pr.logger.Info("REMOTE: Accepted connection from %s", remoteIP)
}

func htons(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}

func interfaceIndex(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return iface.Index, nil
}

func isENXIO(err error) bool {
	return err == unix.ENXIO
}

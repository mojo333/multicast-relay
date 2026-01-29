// Package relay implements the core multicast/broadcast packet relay engine.
package relay

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/alsmith/multicast-relay/internal/cipher"
	"github.com/alsmith/multicast-relay/internal/logger"
	"github.com/alsmith/multicast-relay/internal/netifaces"

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

	udpMaxLength = 1458
	ipv4Len      = 4
)

var magic = []byte("MRLY")

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
	Interfaces          []string
	NoTransmitInterfaces []string
	IfFilter            string
	WaitForIP           bool
	TTL                 int
	OneInterface        bool
	AllowNonEther       bool
	SSDPUnicastAddr     string
	MDNSForceUnicast    bool
	Masquerade          []string
	Listen              []string
	Remote              []string
	RemotePort          int
	RemoteRetry         int
	NoRemoteRelay       bool
	AESKey              string
	Logger              *logger.Logger
}

// PacketRelay is the main relay engine.
type PacketRelay struct {
	interfaces           []string
	noTransmitInterfaces []string
	ifFilter             map[string][]string
	ssdpUnicastAddr      string
	mdnsForceUnicast     bool
	wait                 bool
	ttl                  int
	oneInterface         bool
	allowNonEther        bool
	masquerade           []string

	logger *logger.Logger

	transmitters    []Transmitter
	receivers       []Receiver
	etherAddrs      map[string]net.HardwareAddr
	etherType       []byte
	recentChecksums []uint16
	mu              sync.Mutex

	listenAddr        []string
	listenFd          int
	remoteAddrs       []*RemoteAddr
	remotePort        int
	remoteRetry       int
	noRemoteRelay     bool
	aes               *cipher.Cipher
	remoteConnections []net.Conn
}

// New creates and initializes a new PacketRelay.
func New(cfg Config) (*PacketRelay, error) {
	pr := &PacketRelay{
		interfaces:           cfg.Interfaces,
		noTransmitInterfaces: cfg.NoTransmitInterfaces,
		ifFilter:             make(map[string][]string),
		ssdpUnicastAddr:      cfg.SSDPUnicastAddr,
		mdnsForceUnicast:     cfg.MDNSForceUnicast,
		wait:                 cfg.WaitForIP,
		ttl:                  cfg.TTL,
		oneInterface:         cfg.OneInterface,
		allowNonEther:        cfg.AllowNonEther,
		masquerade:           cfg.Masquerade,
		logger:               cfg.Logger,
		etherAddrs:           make(map[string]net.HardwareAddr),
		etherType:            []byte{0x08, 0x00}, // IPv4
		listenFd:             -1,
		listenAddr:           cfg.Listen,
		remotePort:           cfg.RemotePort,
		remoteRetry:          cfg.RemoteRetry,
		noRemoteRelay:        cfg.NoRemoteRelay,
		aes:                  cipher.New(cfg.AESKey),
	}

	if cfg.IfFilter != "" {
		data, err := os.ReadFile(cfg.IfFilter)
		if err != nil {
			return nil, fmt.Errorf("cannot read ifFilter file %s: %w", cfg.IfFilter, err)
		}
		cleaned := strings.ReplaceAll(strings.TrimSpace(string(data)), "\n", " ")
		if err := json.Unmarshal([]byte(cleaned), &pr.ifFilter); err != nil {
			return nil, fmt.Errorf("cannot parse ifFilter JSON: %w", err)
		}
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
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)

		sa := &unix.SockaddrInet4{Port: pr.remotePort}
		// bind to 0.0.0.0
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
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
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
			unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1)

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
			mreq := make([]byte, 8)
			copy(mreq[0:4], mcastIP)
			copy(mreq[4:8], ifIP)
			unix.SetsockoptString(multicastRxFd, unix.SOL_IP, unix.IP_ADD_MEMBERSHIP, string(mreq))
		}

		// Create transmitter for this interface (unless in noTransmitInterfaces)
		if !pr.isNoTransmit(iface) {
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

	return nil
}

// Loop runs the main packet relay event loop.
func (pr *PacketRelay) Loop() error {
	recentSsdpSearchSrc := map[string]interface{}{}

	buf := make([]byte, 10240)

	for {
		if len(pr.remoteAddrs) > 0 {
			pr.connectRemotes()
		}

		// Build the poll set
		fds := []unix.PollFd{}
		fdMap := map[int]string{} // fd -> "listen", "remote", "receiver"

		if pr.listenFd >= 0 {
			fds = append(fds, unix.PollFd{Fd: int32(pr.listenFd), Events: unix.POLLIN})
			fdMap[pr.listenFd] = "listen"
		}

		// We can't easily poll on net.Conn, so for remote connections we use a goroutine approach below
		for _, rx := range pr.receivers {
			fds = append(fds, unix.PollFd{Fd: int32(rx.fd), Events: unix.POLLIN})
			fdMap[rx.fd] = "receiver"
		}

		if len(fds) == 0 {
			time.Sleep(time.Second)
			continue
		}

		n, err := unix.Poll(fds, 1000) // 1 second timeout
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("poll error: %w", err)
		}
		if n == 0 {
			continue
		}

		for _, pfd := range fds {
			if pfd.Revents&unix.POLLIN == 0 {
				continue
			}
			fd := int(pfd.Fd)

			if fdMap[fd] == "listen" {
				pr.handleListenAccept(fd)
				continue
			}

			// Local receiver
			nread, from, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				pr.logger.Info("Error receiving packet: %s", err)
				continue
			}
			if nread == 0 {
				continue
			}

			data := make([]byte, nread)
			copy(data, buf[:nread])

			var senderAddr string
			if sa, ok := from.(*unix.SockaddrInet4); ok {
				senderAddr = net.IP(sa.Addr[:]).String()
			} else {
				continue
			}

			pr.processPacket(data, senderAddr, "local", recentSsdpSearchSrc)
		}
	}
}

func (pr *PacketRelay) processPacket(data []byte, senderAddr string, receivingInterface string, recentSsdpSearchSrc map[string]interface{}) {
	if len(data) < 28 { // min IP header + UDP header
		return
	}

	// Forward to remote connections
	if len(pr.remoteSockets()) > 0 && !(receivingInterface == "remote" && pr.noRemoteRelay) {
		packet := append(magic, net.ParseIP(senderAddr).To4()...)
		packet = append(packet, data...)
		encrypted, err := pr.aes.Encrypt(packet)
		if err == nil {
			sizeHeader := make([]byte, 2)
			binary.BigEndian.PutUint16(sizeHeader, uint16(len(encrypted)))
			payload := append(sizeHeader, encrypted...)

			for _, conn := range pr.remoteSockets() {
				conn.Write(payload)
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
	pr.mu.Lock()
	for _, cs := range pr.recentChecksums {
		if cs == ipChecksum {
			pr.mu.Unlock()
			return
		}
	}
	pr.mu.Unlock()

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
	ssdpSearch := regexp.MustCompile(`M-SEARCH|NOTIFY`)
	if pr.ssdpUnicastAddr != "" && dstAddr == SSDPMcastAddr && dstPort == SSDPMcastPort && ssdpSearch.Match(data) {
		recentSsdpSearchSrc["addr"] = srcAddr
		recentSsdpSearchSrc["port"] = srcPort
		pr.logger.Info("Last SSDP search source: %s:%d", srcAddr, srcPort)

		srcAddr = pr.ssdpUnicastAddr
		srcPort = SSDPUnicastPort
		data = ModifyUDPPacket(data, ipHeaderLength, srcAddr, srcPort, "", 0)
	} else if pr.ssdpUnicastAddr != "" && origDstAddr == pr.ssdpUnicastAddr && origDstPort == SSDPUnicastPort {
		if _, ok := recentSsdpSearchSrc["addr"]; !ok {
			return
		}
		dstAddr = recentSsdpSearchSrc["addr"].(string)
		dstPort = recentSsdpSearchSrc["port"].(uint16)
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
		transmit := true
		for netStr, allowedIfaces := range pr.ifFilter {
			parts := strings.SplitN(netStr, "/", 2)
			network := parts[0]
			maskBits := "32"
			if len(parts) == 2 {
				maskBits = parts[1]
			}
			var bits int
			fmt.Sscanf(maskBits, "%d", &bits)
			netmask := CIDRToNetmask(bits)
			if OnNetwork(srcAddr, network, netmask) {
				found := false
				for _, iface := range allowedIfaces {
					if iface == tx.Interface {
						found = true
						break
					}
				}
				if !found {
					transmit = false
				}
				break
			}
		}
		if !transmit {
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

			if pr.isMasquerade(tx.Interface) {
				copy(txData[12:16], net.ParseIP(tx.Addr).To4())
			}

			servicePrefix := ""
			if tx.Service != "" {
				servicePrefix = fmt.Sprintf("[%s] ", tx.Service)
			}
			action := "Relayed"
			if pr.isMasquerade(tx.Interface) {
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
					pr.logger.Info("Attempting to recover interface %s", tx.Interface)
					ifInfo, recoverErr := pr.getInterface(tx.Interface)
					if recoverErr == nil {
						newFd, sockErr := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
						if sockErr == nil {
							ifIdx, _ := interfaceIndex(ifInfo.Name)
							sa := &unix.SockaddrLinklayer{
								Protocol: htons(unix.ETH_P_ALL),
								Ifindex:  ifIdx,
							}
							unix.Bind(newFd, sa)
							unix.Close(tx.Socket)
							tx.Socket = newFd
							tx.MAC = ifInfo.MAC
							tx.Netmask = ifInfo.Netmask
							tx.Addr = ifInfo.IP
							pr.transmitPacket(tx, localDestMac, ipHeaderLength, txData)
						}
					}
				} else {
					pr.logger.Info("Error sending packet: %s", err)
				}
			}
		}
	}
}

func (pr *PacketRelay) transmitPacket(tx *Transmitter, destMac net.HardwareAddr, ipHeaderLength int, data []byte) error {
	ipHeader := data[:ipHeaderLength]
	udpHeader := data[ipHeaderLength : ipHeaderLength+8]
	payload := data[ipHeaderLength+8:]

	dontFragment := (data[6] & 0x40) >> 6

	udpHeader = ComputeUDPChecksum(ipHeader, udpHeader, payload)

	zeroMAC := net.HardwareAddr{0, 0, 0, 0, 0, 0}

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
		pr.mu.Lock()
		pr.recentChecksums = append(pr.recentChecksums, cs)
		if len(pr.recentChecksums) > 256 {
			pr.recentChecksums = pr.recentChecksums[1:]
		}
		pr.mu.Unlock()

		var packet []byte
		if !macEqual(tx.MAC, zeroMAC) {
			// Prepend ethernet header: destMac + srcMac + etherType
			packet = make([]byte, 0, 14+len(ipPacket))
			packet = append(packet, destMac...)
			packet = append(packet, tx.MAC...)
			packet = append(packet, pr.etherType...)
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

func (pr *PacketRelay) getInterface(iface string) (*InterfaceResult, error) {
	var info *netifaces.InterfaceInfo
	var err error

	// Try as interface name
	info, err = netifaces.FindByName(iface)

	// Try as IP address
	if err != nil {
		if matched, _ := regexp.MatchString(`^\d+\.\d+\.\d+\.\d+$`, iface); matched {
			info, err = netifaces.FindByIP(iface)
		}
	}

	// Try as CIDR
	if err != nil {
		if matched, _ := regexp.MatchString(`^\d+\.\d+\.\d+\.\d+/\d+$`, iface); matched {
			info, err = netifaces.FindByCIDR(iface)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("interface %s does not exist: %w", iface, err)
	}

	// Wait for IPv4 address if configured
	if pr.wait {
		for info.IP == nil {
			pr.logger.Info("Waiting for IPv4 address on %s", info.Name)
			time.Sleep(time.Second)
			info, err = netifaces.FindByName(info.Name)
			if err != nil {
				return nil, err
			}
		}
	}

	if info.IP == nil {
		return nil, fmt.Errorf("interface %s does not have an IPv4 address assigned", info.Name)
	}

	var mac net.HardwareAddr
	if len(info.MAC) > 0 {
		mac = info.MAC
	} else if pr.allowNonEther {
		mac = net.HardwareAddr{0, 0, 0, 0, 0, 0}
	} else {
		return nil, fmt.Errorf("unable to detect MAC address for interface %s", info.Name)
	}

	netmask := net.IP(info.Netmask).String()
	// net.IPMask.String() returns hex, convert to dotted notation
	if len(info.Netmask) == 4 {
		netmask = fmt.Sprintf("%d.%d.%d.%d", info.Netmask[0], info.Netmask[1], info.Netmask[2], info.Netmask[3])
	}

	broadcast := info.Broadcast.String()

	return &InterfaceResult{
		Name:      info.Name,
		MAC:       mac,
		IP:        info.IP.String(),
		Netmask:   netmask,
		Broadcast: broadcast,
	}, nil
}

func (pr *PacketRelay) isNoTransmit(iface string) bool {
	for _, nt := range pr.noTransmitInterfaces {
		if nt == iface {
			return true
		}
	}
	return false
}

func (pr *PacketRelay) isMasquerade(iface string) bool {
	for _, m := range pr.masquerade {
		if m == iface {
			return true
		}
	}
	return false
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
		return
	}

	pr.remoteConnections = append(pr.remoteConnections, conn)
	pr.logger.Info("REMOTE: Accepted connection from %s", remoteIP)
}

func macEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func htons(v uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return binary.LittleEndian.Uint16(b)
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

// HexMAC returns a colon-separated hex MAC string from a hardware address.
func HexMAC(mac net.HardwareAddr) string {
	if len(mac) == 0 {
		return "00:00:00:00:00:00"
	}
	return mac.String()
}

// ParseMACBytes parses a colon-separated MAC string to raw bytes.
func ParseMACBytes(mac string) ([]byte, error) {
	cleaned := strings.ReplaceAll(mac, ":", "")
	return hex.DecodeString(cleaned)
}

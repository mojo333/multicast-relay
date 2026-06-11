// Package relay implements the core multicast/broadcast packet relay engine.
package relay

import (
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

	udpMaxLength       = 1456 // must be a multiple of 8 for IP fragmentation alignment
	maxRecentChecksums = 256

	// ethPAllBE is ETH_P_ALL in network byte order (big-endian).
	ethPAllBE = (unix.ETH_P_ALL>>8)&0xff | (unix.ETH_P_ALL&0xff)<<8
)

const (
	// maxPacketSize is the maximum expected packet size for pooled buffers.
	maxPacketSize = 10240

	minUDPPacketLen = 28 // min IP(20)+UDP(8) header

	// maxRemoteMessageLen caps the remote TCP framing length prefix. The frame
	// body is magic(4) + senderIP(4) + packet(<=maxPacketSize), plus GCM
	// nonce(12) + tag(16) when AES is enabled.
	maxRemoteMessageLen = maxPacketSize + 4 + 4 + 12 + 16
)

var (
	ipv4EtherType = [2]byte{0x08, 0x00}

	magicBytes = [4]byte{'M', 'R', 'L', 'Y'}
	zeroMAC    = net.HardwareAddr{0, 0, 0, 0, 0, 0}

	ssdpSearchRe = regexp.MustCompile(`M-SEARCH|NOTIFY`)

	ssdpMcastNetip = netip.MustParseAddr(SSDPMcastAddr)
	mdnsMcastNetip = netip.MustParseAddr(MDNSMcastAddr)

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

	aes, err := cipher.New(cfg.AESKey)
	if err != nil {
		return nil, err
	}

	var ssdpUnicast netip.Addr
	if cfg.SSDPUnicastAddr != "" {
		ssdpUnicast, err = netip.ParseAddr(cfg.SSDPUnicastAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid ssdp-unicast-addr %q: %w", cfg.SSDPUnicastAddr, err)
		}
	}

	pr := &PacketRelay{
		interfaces:           cfg.Interfaces,
		noTransmitInterfaces: noTx,
		ssdpUnicastAddr:      ssdpUnicast,
		mdnsForceUnicast:     cfg.MDNSForceUnicast,
		wait:                 cfg.WaitForIP,
		ttl:                  cfg.TTL,
		oneInterface:         cfg.OneInterface,
		allowNonEther:        cfg.AllowNonEther,
		masquerade:           masq,
		logger:               cfg.Logger,
		etherAddrs:           make(map[netip.Addr]net.HardwareAddr),
		remoteReadBufs:       make(map[net.Conn]*remoteReadBuf),
		listenAddr:           cfg.Listen,
		remotePort:           cfg.RemotePort,
		remoteRetry:          cfg.RemoteRetry,
		noRemoteRelay:        cfg.NoRemoteRelay,
		aes:                  aes,
		connsDirty:           true,
		pollDirty:            true,
		done:                 make(chan struct{}),
		remoteTmpBuf:         make([]byte, 4096),
	}

	if cfg.Remote != nil {
		for _, addr := range cfg.Remote {
			pr.remoteAddrs = append(pr.remoteAddrs, &RemoteAddr{Addr: addr})
		}
	}

	if len(pr.remoteAddrs) > 0 || len(cfg.Listen) > 0 {
		pr.connectResultCh = make(chan connectResult, 8)
	}

	if cfg.IfFilter != "" {
		rawFilters, err := parseIfFilterFile(cfg.IfFilter)
		if err != nil {
			return nil, err
		}
		pr.parsedFilters = rawFilters
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

// Close signals the relay loop to stop and cleans up resources.
func (pr *PacketRelay) Close() {
	select {
	case <-pr.done:
		return // already closed
	default:
		close(pr.done)
	}

	// Close listener
	if pr.listener != nil {
		pr.listener.Close()
	}

	// Close all remote connections
	for _, conn := range pr.remoteConnections {
		conn.Close()
	}
	for _, ra := range pr.remoteAddrs {
		if ra.Conn != nil {
			ra.Conn.Close()
		}
	}

	// Close receiver sockets
	for _, rx := range pr.receivers {
		unix.Close(rx.fd)
	}

	// Close transmitter sockets
	for _, tx := range pr.transmitters {
		unix.Close(tx.Socket)
	}
}

// processPacket processes an incoming packet and relays it to other interfaces.
func (pr *PacketRelay) processPacket(data []byte, senderAddr netip.Addr, receivingInterface string) {
	if len(data) < minUDPPacketLen {
		return
	}

	// Dedup check FIRST using the original received checksum, before any modification.
	ipChecksum := binary.BigEndian.Uint16(data[10:12])
	if pr.isDuplicate(ipChecksum) {
		return
	}
	pr.addChecksum(ipChecksum)

	// IP header length
	ipHeaderLength := int(data[0]&0x0f) * 4
	if ipHeaderLength < 20 || ipHeaderLength > len(data)-8 {
		return
	}

	// Forward to remote connections with original TTL (before local TTL rewrite).
	remotes := pr.remoteSockets()
	if len(remotes) > 0 && !(receivingInterface == "remote" && pr.noRemoteRelay) {
		senderIPBytes := senderAddr.As4()
		packet := make([]byte, 0, len(magicBytes)+4+len(data))
		packet = append(packet, magicBytes[:]...)
		packet = append(packet, senderIPBytes[:]...)
		packet = append(packet, data...)

		frame, err := pr.aes.EncryptFrame(packet)
		if err == nil {
			var failed []net.Conn
			for _, conn := range remotes {
				conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
				_, werr := conn.Write(frame)
				conn.SetWriteDeadline(time.Time{})
				if werr != nil {
					pr.logger.Warning("REMOTE: Write error to %s: %s", conn.RemoteAddr(), werr)
					failed = append(failed, conn)
				}
			}
			for _, conn := range failed {
				pr.removeConnection(conn)
				conn.Close()
			}
		}
	}

	// Extract TTL for logging, then apply local TTL override.
	ttl := data[8]
	if pr.ttl > 0 {
		data[8] = byte(pr.ttl)
	}

	srcAddr := AddrFrom4Bytes(data[12:16])
	dstAddr := AddrFrom4Bytes(data[16:20])
	srcPort := binary.BigEndian.Uint16(data[ipHeaderLength : ipHeaderLength+2])
	dstPort := binary.BigEndian.Uint16(data[ipHeaderLength+2 : ipHeaderLength+4])

	origDstAddr := dstAddr
	origDstPort := dstPort

	// mDNS unicast forcing
	data = pr.applyMDNS(data, ipHeaderLength, dstAddr, dstPort)

	// SSDP M-SEARCH / NOTIFY interception
	var destMac net.HardwareAddr
	var drop bool
	data, srcAddr, srcPort, dstAddr, dstPort, destMac, drop = pr.handleSSDP(data, ipHeaderLength, srcAddr, srcPort, dstAddr, dstPort)
	if drop {
		return
	}

	// Determine receiving interface
	broadcastPacket := false
	if receivingInterface == "local" {
		receivingInterface, broadcastPacket = pr.findReceivingIface(senderAddr, origDstAddr, origDstPort)
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
			localDestMac = pr.etherAddrs[broadcastIP]
			localOrigDstAddr = tx.Broadcast
		}

		if localOrigDstAddr == tx.Relay.Addr && int(origDstPort) == tx.Relay.Port &&
			(pr.oneInterface || !OnNetwork(senderAddr, tx.Network)) {

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
				addrBytes := tx.Addr.As4()
				copy(txData[12:16], addrBytes[:])
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
				if err == unix.ENXIO {
					pr.recoverTransmitter(tx, localDestMac, ipHeaderLength, txData)
				} else {
					pr.logger.Warning("Error sending packet: %s", err)
				}
			}
			putBuffer(txBp)
		}
	}
}

// applyMDNS sets the UNICAST-RESPONSE bit in mDNS query packets when mdnsForceUnicast is enabled.
func (pr *PacketRelay) applyMDNS(data []byte, ipHeaderLength int, dstAddr netip.Addr, dstPort uint16) []byte {
	if pr.mdnsForceUnicast && dstAddr == mdnsMcastNetip && dstPort == MDNSMcastPort {
		return MdnsSetUnicastBit(data, ipHeaderLength)
	}
	return data
}

// handleSSDP processes SSDP M-SEARCH interception and unicast reply routing.
// It may modify srcAddr/srcPort (M-SEARCH), dstAddr/dstPort (unicast reply), data, and destMac.
// Returns drop=true when the packet should be silently discarded.
func (pr *PacketRelay) handleSSDP(data []byte, ipHeaderLength int, srcAddr netip.Addr, srcPort uint16, dstAddr netip.Addr, dstPort uint16) (outData []byte, outSrcAddr netip.Addr, outSrcPort uint16, outDstAddr netip.Addr, outDstPort uint16, destMac net.HardwareAddr, drop bool) {
	outData, outSrcAddr, outSrcPort, outDstAddr, outDstPort = data, srcAddr, srcPort, dstAddr, dstPort

	if pr.ssdpUnicastAddr.IsValid() && dstAddr == ssdpMcastNetip && dstPort == SSDPMcastPort && ssdpSearchRe.Match(data[ipHeaderLength+8:]) {
		pr.ssdpSrc.addr = srcAddr
		pr.ssdpSrc.port = srcPort
		pr.ssdpSrc.set = true
		pr.logger.Info("Last SSDP search source: %s:%d", srcAddr, srcPort)

		outSrcAddr = pr.ssdpUnicastAddr
		outSrcPort = SSDPUnicastPort
		outData = ModifyUDPPacket(data, ipHeaderLength, outSrcAddr, outSrcPort, netip.Addr{}, 0)
		return
	}

	if pr.ssdpUnicastAddr.IsValid() && dstAddr == pr.ssdpUnicastAddr && dstPort == SSDPUnicastPort {
		if !pr.ssdpSrc.set {
			drop = true
			return
		}
		outDstAddr = pr.ssdpSrc.addr
		outDstPort = pr.ssdpSrc.port
		pr.logger.Info("Received SSDP Unicast - received from %s:%d on %s:%d, need to relay to %s:%d",
			srcAddr, srcPort, dstAddr, dstPort, outDstAddr, outDstPort)

		outData = ModifyUDPPacket(data, ipHeaderLength, netip.Addr{}, 0, outDstAddr, outDstPort)

		macStr, err := UnicastIPToMAC(outDstAddr.String(), "")
		if err != nil || macStr == "" {
			pr.logger.Info("Could not resolve MAC for %s", outDstAddr)
			drop = true
			return
		}
		destMac, err = net.ParseMAC(macStr)
		if err != nil {
			pr.logger.Info("Could not parse MAC %s: %s", macStr, err)
			drop = true
			return
		}
	}
	return
}

// findReceivingIface identifies which local interface received a packet based on destination.
func (pr *PacketRelay) findReceivingIface(senderAddr, origDstAddr netip.Addr, origDstPort uint16) (ifaceName string, isBroadcast bool) {
	for _, tx := range pr.transmitters {
		if origDstAddr == tx.Relay.Addr && int(origDstPort) == tx.Relay.Port &&
			OnNetwork(senderAddr, tx.Network) {
			ifaceName = tx.Interface
			isBroadcast = (origDstAddr == tx.Broadcast)
			break
		}
	}
	return
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
func (pr *PacketRelay) isAllowedByFilter(srcAddr netip.Addr, txInterface string) bool {
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

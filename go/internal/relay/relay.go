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

	// remoteWriteTimeout bounds a single write to a remote peer inside its writer
	// goroutine. remoteWriteQueueLen bounds how many frames may be buffered for a
	// slow peer before new frames are dropped.
	remoteWriteTimeout  = 100 * time.Millisecond
	remoteWriteQueueLen = 256

	// arpCacheTTL is how long a resolved IP→MAC mapping is reused before the ARP
	// table is re-read for SSDP unicast reply routing.
	arpCacheTTL = 10 * time.Second
)

const (
	// maxPacketSize is the maximum expected packet size for pooled buffers.
	maxPacketSize = 10240

	// maxFrameBufferSize is the largest transmit scratch buffer: a full-size IP
	// packet plus the 14-byte ethernet header. Pooled buffers are sized to this
	// so full-size frames never fall outside the pool's capacity.
	maxFrameBufferSize = 14 + maxPacketSize

	minUDPPacketLen = 28 // min IP(20)+UDP(8) header

	// maxRemoteMessageLen caps the remote TCP framing length prefix. The frame
	// body is seq(8) + magic(4) + senderIP(4) + packet(<=maxPacketSize), plus GCM
	// nonce(12) + tag(16) when AES is enabled.
	maxRemoteMessageLen = maxPacketSize + remoteHeaderLen + 12 + 16

	// remoteHeaderLen is the fixed remote-frame plaintext header preceding the
	// relayed IP packet: seq(8) + magic(4) + senderIP(4).
	remoteHeaderLen = 8 + len(magicBytes) + 4
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
			b := make([]byte, 0, maxFrameBufferSize)
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
		remoteWriters:        make(map[net.Conn]*remoteWriter),
		remotePacketCh:       make(chan remotePacket, 256),
		remoteFailedCh:       make(chan net.Conn, 16),
		listenAddr:           cfg.Listen,
		remotePort:           cfg.RemotePort,
		remoteRetry:          cfg.RemoteRetry,
		noRemoteRelay:        cfg.NoRemoteRelay,
		aes:                  aes,
		connsDirty:           true,
		pollDirty:            true,
		done:                 make(chan struct{}),
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

	// Dedup: drop the packet if its IP checksum matches one we recently put on
	// the wire ourselves (see transmitPacket, which records transmitted
	// checksums). This suppresses the relay's own retransmissions looping back on
	// a listening interface. The received checksum is only checked, never
	// recorded here — recording it would not match the modified packet we later
	// transmit (e.g. after a TTL or masquerade rewrite).
	ipChecksum := binary.BigEndian.Uint16(data[10:12])
	if pr.isDuplicate(ipChecksum) {
		return
	}

	// IP header length
	ipHeaderLength := int(data[0]&0x0f) * 4
	if ipHeaderLength < 20 || ipHeaderLength > len(data)-8 {
		return
	}

	// Forward to remote connections with original TTL (before local TTL rewrite).
	remotes := pr.remoteSockets()
	if len(remotes) > 0 && !(receivingInterface == "remote" && pr.noRemoteRelay) {
		senderIPBytes := senderAddr.As4()
		seq := pr.remoteSeq
		pr.remoteSeq++
		// Frame plaintext: seq(8) || magic(4) || senderIP(4) || packet.
		// The sequence number lets the peer reject replayed frames.
		packet := make([]byte, 0, remoteHeaderLen+len(data))
		var seqBytes [8]byte
		binary.BigEndian.PutUint64(seqBytes[:], seq)
		packet = append(packet, seqBytes[:]...)
		packet = append(packet, magicBytes[:]...)
		packet = append(packet, senderIPBytes[:]...)
		packet = append(packet, data...)

		frame, err := pr.aes.EncryptFrame(packet)
		if err == nil {
			// Hand the frame to each connection's writer goroutine instead of
			// writing inline: a slow or stalled remote peer must never block the
			// single-threaded event loop and stall local relaying.
			for _, conn := range remotes {
				pr.queueRemoteFrame(conn, frame)
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
	} else if receivingInterface == "remote" {
		// A broadcast packet arriving over the remote relay carries the sending
		// site's subnet broadcast as its destination, which never equals any
		// local interface's broadcast. Recognize it here so it can be re-broadcast
		// onto local interfaces instead of being silently dropped.
		broadcastPacket = pr.isRemoteBroadcast(origDstAddr, origDstPort)
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

			// Only take a private copy when masquerading rewrites the source
			// address; otherwise transmitPacket reads data without mutating it, so
			// the received buffer can be passed through directly.
			isMasq := pr.masquerade[tx.Interface]
			txData := data
			var txBp *[]byte
			if isMasq {
				txBp = getBuffer(len(data))
				txData = *txBp
				copy(txData, data)
				addrBytes := tx.Addr.As4()
				copy(txData[12:16], addrBytes[:])
			}

			if pr.logger.InfoEnabled() {
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
			}

			if err := pr.transmitPacket(tx, localDestMac, ipHeaderLength, txData); err != nil {
				// Try to recover if ENXIO (device not configured)
				if err == unix.ENXIO {
					pr.recoverTransmitter(tx, localDestMac, ipHeaderLength, txData)
				} else {
					pr.logger.Warning("Error sending packet: %s", err)
				}
			}
			if txBp != nil {
				putBuffer(txBp)
			}
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

		destMac, err := pr.resolveUnicastMAC(outDstAddr)
		if err != nil || destMac == nil {
			pr.logger.Info("Could not resolve MAC for %s", outDstAddr)
			drop = true
			return outData, outSrcAddr, outSrcPort, outDstAddr, outDstPort, nil, true
		}
		return outData, outSrcAddr, outSrcPort, outDstAddr, outDstPort, destMac, false
	}
	return
}

// resolveUnicastMAC resolves an IP to a MAC via the ARP table, caching the most
// recent lookup for a short TTL. SSDP unicast replies arrive in bursts to the
// same source, so this avoids re-reading and re-parsing /proc/net/arp per packet.
// Called only from the main loop goroutine.
func (pr *PacketRelay) resolveUnicastMAC(ip netip.Addr) (net.HardwareAddr, error) {
	ipStr := ip.String()
	now := time.Now()
	if pr.arpCacheMAC != nil && pr.arpCacheIP == ipStr && now.Sub(pr.arpCacheTime) < arpCacheTTL {
		return pr.arpCacheMAC, nil
	}
	macStr, err := UnicastIPToMAC(ipStr, "")
	if err != nil || macStr == "" {
		return nil, err
	}
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		pr.logger.Info("Could not parse MAC %s: %s", macStr, err)
		return nil, err
	}
	pr.arpCacheIP = ipStr
	pr.arpCacheMAC = mac
	pr.arpCacheTime = now
	return mac, nil
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

// isRemoteBroadcast reports whether a packet arriving over the remote relay is a
// broadcast that should be re-broadcast onto local interfaces. Remote packets are
// only ever forwarded because they matched a relay rule on the sender, so any
// non-multicast packet whose destination port matches a configured broadcast
// transmitter (Relay.Addr == the interface broadcast) is a relayed broadcast.
func (pr *PacketRelay) isRemoteBroadcast(origDstAddr netip.Addr, origDstPort uint16) bool {
	if origDstAddr.IsMulticast() {
		return false
	}
	for i := range pr.transmitters {
		tx := &pr.transmitters[i]
		if int(origDstPort) == tx.Relay.Port && tx.Relay.Addr == tx.Broadcast {
			return true
		}
	}
	return false
}

// queueRemoteFrame hands a wire frame to the connection's writer goroutine via a
// bounded queue. If the queue is full (a slow or stalled peer), the frame is
// dropped rather than blocking the event loop — discovery traffic tolerates loss.
// The writer goroutine is created lazily on first use. Called only from the main
// loop goroutine, so remoteWriters access needs no locking.
func (pr *PacketRelay) queueRemoteFrame(conn net.Conn, frame []byte) {
	w := pr.remoteWriters[conn]
	if w == nil {
		w = &remoteWriter{conn: conn, ch: make(chan []byte, remoteWriteQueueLen), done: make(chan struct{})}
		pr.remoteWriters[conn] = w
		go pr.runWriter(w)
	}
	select {
	case w.ch <- frame:
	default:
		pr.logger.Info("REMOTE: Write queue full for %s — dropping frame", conn.RemoteAddr())
	}
}

// runWriter drains a connection's frame queue and writes frames to the socket.
// On a write error it closes the connection; the main loop's reader observes the
// closure and cleans up. Exits when the connection is removed or the relay stops.
func (pr *PacketRelay) runWriter(w *remoteWriter) {
	for {
		select {
		case <-w.done:
			return
		case <-pr.done:
			return
		case frame := <-w.ch:
			w.conn.SetWriteDeadline(time.Now().Add(remoteWriteTimeout))
			_, err := w.conn.Write(frame)
			w.conn.SetWriteDeadline(time.Time{})
			if err != nil {
				w.conn.Close()
				return
			}
		}
	}
}

// stopWriter tears down a connection's writer goroutine, if any.
// Called only from the main loop goroutine.
func (pr *PacketRelay) stopWriter(conn net.Conn) {
	if w := pr.remoteWriters[conn]; w != nil {
		close(w.done)
		delete(pr.remoteWriters, conn)
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

// Package relay implements the core multicast/broadcast packet relay engine.
package relay

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/maphash"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mojo333/multicast-relay/internal/cipher"
)

// Protocol constants matching the Python version.
const (
	BroadcastAddr   = "255.255.255.255"
	SSDPMcastAddr   = "239.255.255.250"
	SSDPMcastPort   = 1900
	SSDPUnicastPort = 1901
	MDNSMcastAddr   = "224.0.0.251"
	MDNSMcastPort   = 5353

	udpMaxLength     = 1456 // must be a multiple of 8 for IP fragmentation alignment
	maxRecentPackets = 256

	// dedupWindow is how long a packet is remembered. Loops come back within
	// milliseconds, while a longer memory would swallow genuine repeats from
	// devices that never change their IP packet ID.
	dedupWindow = 2 * time.Second

	// remoteWriteTimeout bounds a single write to a remote peer inside its writer
	// goroutine. remoteWriteQueueLen bounds how many frames may be buffered for a
	// slow peer before new frames are dropped.
	remoteWriteTimeout  = 5 * time.Second
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

	ssdpSearchPrefix = []byte("M-SEARCH")

	// dedupSeed keys the duplicate filter's hash for this process.
	dedupSeed = maphash.MakeSeed()

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
		matchedNames:         make(map[string]string),
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
	seen := make(map[netip.Prefix]bool, len(raw))
	for netStr, ifaces := range raw {
		// If no CIDR suffix, default to /32
		if !strings.Contains(netStr, "/") {
			netStr += "/32"
		}
		prefix, err := netip.ParsePrefix(netStr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR in ifFilter key %q: %w", netStr, err)
		}
		prefix = prefix.Masked()
		if seen[prefix] {
			return nil, fmt.Errorf("ifFilter has more than one rule for %s", prefix)
		}
		seen[prefix] = true
		filters = append(filters, parsedFilter{
			prefix: prefix,
			ifaces: ifaces,
		})
	}
	// The most specific rule wins. Map iteration order must not decide it.
	slices.SortFunc(filters, func(a, b parsedFilter) int {
		return cmp.Or(cmp.Compare(b.prefix.Bits(), a.prefix.Bits()), a.prefix.Addr().Compare(b.prefix.Addr()))
	})
	return filters, nil
}

// Close signals the relay loop to stop. The loop owns the sockets and closes
// them as it returns, so Close is safe to call from another goroutine.
func (pr *PacketRelay) Close() {
	pr.closeOnce.Do(func() {
		close(pr.done)
		if pr.listener != nil {
			pr.listener.Close()
		}
	})
}

// cleanUp closes the remote connections and the relay sockets.
func (pr *PacketRelay) cleanUp() {
	for _, conn := range pr.remoteSockets() {
		conn.Close()
	}
	closeSockets(pr.receivers, pr.transmitters)
	pr.receivers, pr.transmitters = nil, nil
}

// processPacket processes an incoming packet and relays it to other interfaces.
// receivingInterface is a local interface name, "local" when the sender's address
// has to identify it, or "remote" with from set to the connection it arrived on.
func (pr *PacketRelay) processPacket(data []byte, senderAddr netip.Addr, receivingInterface string, from net.Conn) {
	if len(data) < minUDPPacketLen {
		return
	}

	// IP header length
	ipHeaderLength := int(data[0]&0x0f) * 4
	if ipHeaderLength < 20 || ipHeaderLength > len(data)-8 {
		return
	}

	// Remember the packet as received. transmitPacket also remembers it as sent,
	// which stops a rewritten packet looping on a local interface.
	key := dedupKey(data, ipHeaderLength)
	if pr.isDuplicate(key) {
		return
	}
	pr.remember(key)

	srcAddr := AddrFrom4Bytes(data[12:16])
	dstAddr := AddrFrom4Bytes(data[16:20])
	srcPort := binary.BigEndian.Uint16(data[ipHeaderLength : ipHeaderLength+2])
	dstPort := binary.BigEndian.Uint16(data[ipHeaderLength+2 : ipHeaderLength+4])

	origSrcAddr := srcAddr
	origDstAddr := dstAddr
	origDstPort := dstPort

	// Determine receiving interface
	broadcastPacket := false
	switch receivingInterface {
	case "local":
		receivingInterface, broadcastPacket = pr.findReceivingIface(senderAddr, origDstAddr)
	case "remote":
		// A broadcast packet arriving over the remote relay carries the sending
		// site's subnet broadcast as its destination, which never equals any
		// local interface's broadcast. Recognize it here so it can be re-broadcast
		// onto local interfaces instead of being silently dropped.
		broadcastPacket = pr.isRemoteBroadcast(origDstAddr, origDstPort)
	default:
		broadcastPacket = pr.isBroadcastOn(receivingInterface, origDstAddr)
	}

	// SSDP unicast replies arrive on an ordinary address, which any network can
	// reach, so only accept them from a listed one.
	if pr.ssdpUnicastAddr.IsValid() && origDstAddr == pr.ssdpUnicastAddr &&
		receivingInterface == "" && !pr.oneInterface {
		return
	}

	// Forward to remote connections with original TTL (before local TTL rewrite).
	// Local receive sockets also see other ports, which stay on this site.
	var remotes []net.Conn
	switch {
	case receivingInterface == "remote":
		if !pr.noRemoteRelay {
			remotes = pr.remoteSockets()
		}
	case pr.isRelayed(origDstAddr, origDstPort, broadcastPacket):
		remotes = pr.remoteSockets()
	}
	if len(remotes) > 0 {
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

		// Hand the packet to each connection's writer goroutine instead of
		// writing inline: a slow or stalled remote peer must never block the
		// single-threaded event loop and stall local relaying.
		for _, conn := range remotes {
			if conn != from {
				pr.queueRemoteFrame(conn, packet)
			}
		}
	}

	// A service on this host sends on each local network itself, so copying its
	// packets between them would only repeat them. Remote sites still need them.
	if receivingInterface != "remote" && pr.isHostAddr(senderAddr) {
		return
	}

	// Extract TTL for logging, then apply local TTL override.
	ttl := data[8]
	if pr.ttl > 0 {
		data[8] = byte(pr.ttl)
	}

	// mDNS unicast forcing
	data = pr.applyMDNS(data, ipHeaderLength, dstAddr, dstPort)

	// SSDP M-SEARCH interception and unicast reply routing
	var destMac net.HardwareAddr
	var drop bool
	data, srcAddr, srcPort, dstAddr, dstPort, destMac, drop = pr.handleSSDP(data, ipHeaderLength, srcAddr, srcPort, dstAddr, dstPort)
	if drop {
		return
	}

	// Relay to all other interfaces
	for i := range pr.transmitters {
		tx := &pr.transmitters[i]

		if receivingInterface == tx.Interface {
			continue
		}

		// Apply ifFilter to the real sender, not a rewritten source address.
		if !pr.isAllowedByFilter(origSrcAddr, tx.Interface) {
			continue
		}

		// A resolved unicast reply belongs only on the searcher's network.
		if destMac != nil && !pr.oneInterface && !tx.Network.Contains(dstAddr) {
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
			(pr.oneInterface || !tx.Network.Contains(senderAddr)) {
			if localDestMac == nil {
				localDestMac = pr.etherAddrs[localDstAddr]
			}
			if localDestMac == nil {
				continue
			}

			// Only take a private copy when an address is rewritten; otherwise
			// transmitPacket reads data without mutating it, so the received buffer
			// can be passed through directly.
			isMasq := pr.masquerade[tx.Interface]
			txData := data
			var txBp *[]byte
			if isMasq || broadcastPacket {
				txBp = getBuffer(len(data))
				txData = *txBp
				copy(txData, data)
				if isMasq {
					addrBytes := tx.Addr.As4()
					copy(txData[12:16], addrBytes[:])
				}
				if broadcastPacket {
					bcastBytes := tx.Broadcast.As4()
					copy(txData[16:20], bcastBytes[:])
				}
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

			pr.noteSendResult(tx, pr.transmitPacket(tx, localDestMac, ipHeaderLength, txData))
			if txBp != nil {
				putBuffer(txBp)
			}
		}
	}
}

// noteSendResult logs when sending on a transmitter starts failing and when it
// works again, rather than once for every packet in between.
func (pr *PacketRelay) noteSendResult(tx *Transmitter, err error) {
	switch {
	case err != nil && !tx.sendFailing:
		pr.logger.Warning("Error sending packet on %s: %s", tx.Interface, err)
	case err == nil && tx.sendFailing:
		pr.logger.Warning("Sending on %s works again", tx.Interface)
	}
	tx.sendFailing = err != nil
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

	// Announcements (NOTIFY) are not searches and must not take over the replies.
	if pr.ssdpUnicastAddr.IsValid() && dstAddr == ssdpMcastNetip && dstPort == SSDPMcastPort && bytes.HasPrefix(data[ipHeaderLength+8:], ssdpSearchPrefix) {
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

// findReceivingIface identifies the listed interface whose network the sender
// is on, and whether the packet was that network's broadcast.
func (pr *PacketRelay) findReceivingIface(senderAddr, origDstAddr netip.Addr) (ifaceName string, isBroadcast bool) {
	for _, l := range pr.listed {
		if l.info.Network.Contains(senderAddr) {
			return l.info.Name, origDstAddr == l.info.Broadcast
		}
	}
	return "", false
}

// isHostAddr reports whether addr is this host's own address on a listed
// interface.
// shortcut: knows one address per interface, so packets sent from a secondary
// address are still copied. Read every address if a host needs that.
func (pr *PacketRelay) isHostAddr(addr netip.Addr) bool {
	return slices.ContainsFunc(pr.listed, func(l listedInterface) bool { return l.info.Addr == addr })
}

// isBroadcastOn reports whether addr is the named interface's broadcast address.
func (pr *PacketRelay) isBroadcastOn(ifaceName string, addr netip.Addr) bool {
	for _, l := range pr.listed {
		if l.info.Name == ifaceName {
			return l.info.Broadcast == addr
		}
	}
	return false
}

// isRelayed reports whether a locally received packet matches a relay rule.
// Broadcast rules are written as 255.255.255.255 and cover every listed
// network's broadcast address.
func (pr *PacketRelay) isRelayed(dst netip.Addr, port uint16, broadcast bool) bool {
	if !broadcast {
		broadcast = slices.ContainsFunc(pr.listed, func(l listedInterface) bool { return l.info.Broadcast == dst })
	}
	return slices.ContainsFunc(pr.relays, func(r relayRule) bool {
		return r.port == int(port) && (r.addr == dst || broadcast && r.addr == broadcastIP)
	})
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

// queueRemoteFrame hands a frame's plaintext to the connection's writer goroutine
// via a bounded queue. If the queue is full (a slow or stalled peer), the frame is
// dropped rather than blocking the event loop, as discovery traffic tolerates loss.
// The plaintext is shared between writers, so it must not be modified. The writer
// goroutine is created lazily on first use. Called only from the main loop
// goroutine, so remoteWriters access needs no locking.
func (pr *PacketRelay) queueRemoteFrame(conn net.Conn, plaintext []byte) {
	w := pr.remoteWriters[conn]
	if w == nil {
		w = &remoteWriter{conn: conn, ch: make(chan []byte, remoteWriteQueueLen), done: make(chan struct{})}
		pr.remoteWriters[conn] = w
		go pr.runWriter(w)
	}
	select {
	case w.ch <- plaintext:
	default:
		pr.logger.Info("REMOTE: Write queue full for %s — dropping frame", conn.RemoteAddr())
	}
}

// runWriter drains a connection's frame queue, encrypts each frame and writes it
// to the socket. On a write error it closes the connection; the main loop's
// reader observes the closure and cleans up. Exits when the connection is removed
// or the relay stops.
func (pr *PacketRelay) runWriter(w *remoteWriter) {
	aes, _ := pr.connCiphers(w.conn)
	for {
		select {
		case <-w.done:
			return
		case <-pr.done:
			return
		case plaintext := <-w.ch:
			frame, err := aes.EncryptFrame(plaintext)
			if err != nil {
				pr.logger.Warning("REMOTE: Cannot frame packet for %s: %s", w.conn.RemoteAddr(), err)
				continue
			}
			w.conn.SetWriteDeadline(time.Now().Add(remoteWriteTimeout))
			_, err = w.conn.Write(frame)
			w.conn.SetWriteDeadline(time.Time{})
			if err != nil {
				// net.ErrClosed means we closed it ourselves, which is not a fault.
				if !errors.Is(err, net.ErrClosed) {
					pr.logger.Warning("REMOTE: Write error to %s: %s", w.conn.RemoteAddr(), err)
				}
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

// dedupKey fingerprints the parts of a packet that stay the same when it loops
// back: IP ID, TTL, addresses, ports and payload. Lengths, fragment fields and
// checksums are left out so that a reassembled packet still matches.
func dedupKey(packet []byte, ipHeaderLength int) uint64 {
	var h maphash.Hash
	h.SetSeed(dedupSeed)
	h.Write(packet[4:6])
	h.WriteByte(packet[8])
	h.Write(packet[12:20])
	h.Write(packet[ipHeaderLength : ipHeaderLength+4])
	h.Write(packet[ipHeaderLength+8:])
	return h.Sum64()
}

// isDuplicate checks whether this packet was seen within dedupWindow.
// Not safe for concurrent use — only call from the main loop goroutine.
func (pr *PacketRelay) isDuplicate(key uint64) bool {
	now := time.Now()
	for i := range pr.recent {
		if pr.recent[i].key == key && now.Sub(pr.recent[i].at) < dedupWindow {
			return true
		}
	}
	return false
}

// remember records a packet in the ring buffer.
// Not safe for concurrent use — only call from the main loop goroutine.
func (pr *PacketRelay) remember(key uint64) {
	pr.recent[pr.recentIdx] = seenPacket{key: key, at: time.Now()}
	pr.recentIdx = (pr.recentIdx + 1) % maxRecentPackets
}

// isAllowedByFilter checks the pre-parsed ifFilter rules.
func (pr *PacketRelay) isAllowedByFilter(srcAddr netip.Addr, txInterface string) bool {
	for _, f := range pr.parsedFilters {
		if f.prefix.Contains(srcAddr) {
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

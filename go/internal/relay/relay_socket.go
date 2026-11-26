package relay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"golang.org/x/sys/unix"
)

// ifaceCheckInterval is how often the loop looks for recreated or readdressed
// interfaces.
const ifaceCheckInterval = 2 * time.Second

// AddListener sets up receive and transmit sockets for a relay address.
func (pr *PacketRelay) AddListener(addr string, port int, service string) error {
	addrN, err := netip.ParseAddr(addr)
	if err != nil {
		return fmt.Errorf("invalid relay address %q: %w", addr, err)
	}
	rule := relayRule{addr: addrN, port: port, service: service}
	if err := pr.openRule(rule, pr.wait); err != nil {
		return err
	}
	pr.relays = append(pr.relays, rule)
	return nil
}

// openRule opens the sockets for one relay rule on every listed interface. When
// wait is true it blocks until each interface has an IPv4 address.
func (pr *PacketRelay) openRule(rule relayRule, wait bool) (err error) {
	addr := rule.addr.String()
	isBroadcast, isMulticast := IsBroadcast(addr), IsMulticast(addr)
	switch {
	case isBroadcast:
		pr.etherAddrs[rule.addr] = BroadcastIPToMAC()
	case isMulticast:
		pr.etherAddrs[rule.addr] = MulticastIPToMAC(addr)
	default:
		pr.etherAddrs[rule.addr] = nil
	}

	// Multicast and unicast rules use one receive socket for all interfaces.
	shared := -1
	if !isBroadcast {
		if shared, err = newReceiveSocket(); err != nil {
			return err
		}
		defer func() {
			if err != nil {
				unix.Close(shared)
			}
		}()
	}
	if isMulticast {
		// Without this the socket also receives the group from any interface on
		// which some other program joined it, listed or not.
		if err = unix.SetsockoptInt(shared, unix.SOL_IP, unix.IP_MULTICAST_ALL, 0); err != nil {
			return fmt.Errorf("cannot clear IP_MULTICAST_ALL: %w", err)
		}
	}

	for _, spec := range pr.interfaces {
		ifInfo, err := pr.resolveInterfaceWait(spec, wait)
		if err != nil {
			return err
		}
		pr.listInterface(spec, ifInfo)

		if isBroadcast {
			// Devices use either the subnet's broadcast address or the limited one.
			for _, bindAddr := range []netip.Addr{ifInfo.Broadcast, broadcastIP} {
				rx, err := openBroadcastReceiver(ifInfo.Name, bindAddr, rule.port)
				if err != nil {
					return err
				}
				if bindAddr == broadcastIP {
					rx.readdressAs = ifInfo.Broadcast
				}
				pr.receivers = append(pr.receivers, rx)
			}
		} else if isMulticast {
			mreq := &unix.IPMreq{Multiaddr: rule.addr.As4(), Interface: ifInfo.Addr.As4()}
			if err := unix.SetsockoptIPMreq(shared, unix.SOL_IP, unix.IP_ADD_MEMBERSHIP, mreq); err != nil {
				return fmt.Errorf("cannot join multicast group %s on %s: %w", addr, ifInfo.Name, err)
			}
		}

		// Create transmitter for this interface (unless in noTransmitInterfaces)
		if !pr.noTransmitInterfaces[ifInfo.Name] {
			txFd, err := createTransmitSocket(ifInfo)
			if err != nil {
				return err
			}

			listenNetip := rule.addr
			if isBroadcast {
				listenNetip = ifInfo.Broadcast
			}

			pr.transmitters = append(pr.transmitters, Transmitter{
				Relay:     RelayAddr{Addr: listenNetip, Port: rule.port},
				Interface: ifInfo.Name,
				Addr:      ifInfo.Addr,
				MAC:       ifInfo.MAC,
				Network:   ifInfo.Network,
				Broadcast: ifInfo.Broadcast,
				Socket:    txFd,
				Service:   rule.service,
			})
		}
	}

	if shared >= 0 {
		sa := &unix.SockaddrInet4{Port: rule.port, Addr: rule.addr.As4()}
		if err = unix.Bind(shared, sa); err != nil {
			return fmt.Errorf("cannot bind receive socket to %s:%d: %w", addr, rule.port, err)
		}
		pr.receivers = append(pr.receivers, Receiver{fd: shared, port: rule.port})
	}

	pr.pollDirty = true
	return nil
}

// newReceiveSocket creates a raw UDP socket that can share its address.
func newReceiveSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_UDP)
	if err != nil {
		return -1, fmt.Errorf("cannot create receive socket: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("cannot set SO_REUSEADDR: %w", err)
	}
	return fd, nil
}

// openBroadcastReceiver receives one broadcast address on one interface only.
func openBroadcastReceiver(ifName string, addr netip.Addr, port int) (rx Receiver, err error) {
	fd, err := newReceiveSocket()
	if err != nil {
		return rx, err
	}
	defer func() {
		if err != nil {
			unix.Close(fd)
		}
	}()
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1); err != nil {
		return rx, fmt.Errorf("cannot set SO_BROADCAST: %w", err)
	}
	if err = unix.BindToDevice(fd, ifName); err != nil {
		return rx, fmt.Errorf("cannot bind broadcast socket to %s: %w", ifName, err)
	}
	if err = unix.Bind(fd, &unix.SockaddrInet4{Port: port, Addr: addr.As4()}); err != nil {
		return rx, fmt.Errorf("cannot bind broadcast socket to %s:%d: %w", addr, port, err)
	}
	return Receiver{fd: fd, port: port, iface: ifName}, nil
}

// listInterface records a listed interface, and extends the listen-only and
// masquerade sets to its real name when they refer to it in another way.
func (pr *PacketRelay) listInterface(spec string, info *InterfaceResult) {
	if slices.ContainsFunc(pr.listed, func(l listedInterface) bool { return l.spec == spec }) {
		return
	}
	pr.listed = append(pr.listed, listedInterface{spec: spec, info: *info})
	for _, set := range []map[string]bool{pr.noTransmitInterfaces, pr.masquerade} {
		if selects(set, spec, info.Name) {
			set[info.Name] = true
		}
	}
}

// selects reports whether a set of interface specs (names, addresses or CIDR
// blocks) refers to the interface called name and listed as spec.
func selects(set map[string]bool, spec, name string) bool {
	if set[spec] || set[name] {
		return true
	}
	for other := range set {
		if r, err := resolveInterface(other); err == nil && r.Name == name {
			return true
		}
	}
	return false
}

// reopenChangedInterfaces reopens every socket once a listed interface has been
// recreated or readdressed. It returns an error only when the relay can no longer
// open sockets and has to be restarted.
//
// shortcut: waits until every listed interface is usable, reopen them one by one
// if a permanently missing interface must not hold the others back.
func (pr *PacketRelay) reopenChangedInterfaces() error {
	changed, usable := false, true
	for i := range pr.listed {
		l := &pr.listed[i]
		current, err := pr.resolveInterfaceWait(l.spec, false)
		if err != nil {
			if !l.missing {
				pr.logger.Warning("Interface %s is unavailable: %s", l.spec, err)
				l.missing = true
			}
			usable = false
			continue
		}
		l.missing = false
		changed = changed || !current.equal(&l.info)
	}
	if !changed || !usable {
		return nil
	}

	listed, receivers, transmitters := pr.listed, pr.receivers, pr.transmitters
	pr.listed, pr.receivers, pr.transmitters = nil, nil, nil
	for _, rule := range pr.relays {
		if err := pr.openRule(rule, false); err != nil {
			closeSockets(pr.receivers, pr.transmitters)
			pr.listed, pr.receivers, pr.transmitters = listed, receivers, transmitters
			if errors.Is(err, unix.EPERM) {
				return fmt.Errorf("interfaces changed and privileges have been dropped, restart the relay: %w", err)
			}
			if !pr.reopenFailed {
				pr.logger.Warning("Interfaces changed but sockets cannot be reopened yet: %s", err)
				pr.reopenFailed = true
			}
			return nil
		}
	}
	closeSockets(receivers, transmitters)
	pr.reopenFailed = false
	pr.logger.Warning("Interfaces changed, sockets reopened")
	return nil
}

// closeSockets closes receive and transmit sockets.
func closeSockets(receivers []Receiver, transmitters []Transmitter) {
	for _, rx := range receivers {
		unix.Close(rx.fd)
	}
	for _, tx := range transmitters {
		unix.Close(tx.Socket)
	}
}

// rebuildPollFds rebuilds the pre-allocated poll fd set.
func (pr *PacketRelay) rebuildPollFds() {
	pr.pollFds = make([]unix.PollFd, 0, len(pr.receivers))

	for _, rx := range pr.receivers {
		pr.pollFds = append(pr.pollFds, unix.PollFd{Fd: int32(rx.fd), Events: unix.POLLIN})
	}

	pr.pollDirty = false
}

// InterfaceResult holds resolved interface information.
type InterfaceResult struct {
	Name      string
	Index     int
	MAC       net.HardwareAddr
	Addr      netip.Addr
	Network   netip.Prefix
	Broadcast netip.Addr
}

// equal reports whether two results describe the same interface and addresses.
func (r *InterfaceResult) equal(o *InterfaceResult) bool {
	return r.Name == o.Name && r.Index == o.Index && r.Addr == o.Addr && r.Network == o.Network &&
		r.Broadcast == o.Broadcast && bytes.Equal(r.MAC, o.MAC)
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

			ones, _ := net.IPMask(mask).Size()

			return &InterfaceResult{
				Name:      iface.Name,
				Index:     iface.Index,
				MAC:       iface.HardwareAddr,
				Addr:      ifAddr,
				Network:   netip.PrefixFrom(ifAddr, ones).Masked(),
				Broadcast: netip.AddrFrom4(bcastBytes),
			}, nil
		}

		// No usable address yet: return the name so that --wait can retry it.
		if nameMatch {
			return &InterfaceResult{Name: iface.Name, Index: iface.Index, MAC: iface.HardwareAddr}, nil
		}
	}

	return nil, fmt.Errorf("interface %s not found", spec)
}

// resolveInterfaceWait resolves an interface spec. When wait is true it blocks
// (checking pr.done) until the interface has an IPv4 address. Callers on the
// event-loop goroutine must pass wait=false so a missing address cannot stall
// the entire relay.
func (pr *PacketRelay) resolveInterfaceWait(iface string, wait bool) (*InterfaceResult, error) {
	result, err := resolveInterface(iface)
	if err != nil {
		return nil, err
	}

	// Wait for IPv4 address if configured
	if wait && !result.Addr.IsValid() {
		for {
			select {
			case <-pr.done:
				return nil, fmt.Errorf("shutting down while waiting for IPv4 address on %s", result.Name)
			default:
			}
			pr.logger.Info("Waiting for IPv4 address on %s", result.Name)
			time.Sleep(time.Second)
			result, err = resolveInterface(result.Name)
			if err != nil {
				return nil, err
			}
			if result.Addr.IsValid() {
				break
			}
		}
	}

	if !result.Addr.IsValid() {
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

// transmitPacket builds ethernet frames and sends a packet via a transmitter socket.
// Uses a pooled scratch buffer to avoid per-fragment heap allocations.
// Implements proper IP fragmentation per RFC 791: fragment offsets in 8-byte units,
// only the first fragment includes the transport header, and boundaries are 8-byte aligned.
func (pr *PacketRelay) transmitPacket(tx *Transmitter, destMac net.HardwareAddr, ipHeaderLength int, data []byte) error {
	ipHeader := data[:ipHeaderLength]
	udpHeader := data[ipHeaderLength : ipHeaderLength+8]
	payload := data[ipHeaderLength+8:]

	dontFragment := (data[6] & 0x40) >> 6

	// Recompute the UDP checksum into a local 8-byte header (no heap allocation).
	// The IP payload to fragment is the virtual concatenation of newUDPHeader and payload.
	var newUDPHeader [8]byte
	copy(newUDPHeader[:], udpHeader[:6])
	binary.BigEndian.PutUint16(newUDPHeader[6:8], udpChecksumValue(ipHeader, udpHeader, payload))

	hasEther := !bytes.Equal(tx.MAC, zeroMAC)

	// Remember the packet as sent (post TTL, masquerade and SSDP rewrite) so the
	// relay recognizes it if it loops back on a listening interface.
	pr.remember(dedupKey(data, ipHeaderLength))

	ipPayloadLen := 8 + len(payload)

	// Get a scratch buffer large enough for the largest frame: 14 (ether) + IP header + max fragment
	maxFrameSize := 14 + ipHeaderLength + ipPayloadLen
	scratchBp := getBuffer(maxFrameSize)
	defer putBuffer(scratchBp)
	scratch := *scratchBp

	for boundary := 0; boundary < ipPayloadLen; boundary += udpMaxLength {
		end := boundary + udpMaxLength
		if end > ipPayloadLen {
			end = ipPayloadLen
		}
		fragLen := end - boundary
		totalLength := ipHeaderLength + fragLen
		moreFragments := end < ipPayloadLen

		// Fragment offset is in 8-byte units per RFC 791
		flagsOffset := uint16((boundary / 8) & 0x1fff)
		if moreFragments {
			flagsOffset |= 0x2000
		} else if dontFragment != 0 && boundary == 0 {
			// Only preserve the Don't-Fragment bit when the datagram fit in a
			// single fragment. Stamping DF on the tail of a fragment train would
			// be self-contradictory.
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

		// Copy the fragment data directly from the virtual [newUDPHeader || payload]
		// range, so the first fragment includes the UDP header and later ones don't.
		copyIPPayloadRange(scratch[etherOff+ipHeaderLength:], newUDPHeader[:], payload, boundary, end)

		ipPacket := scratch[etherOff : etherOff+totalLength]
		ComputeIPChecksum(ipPacket, ipHeaderLength)

		var frame []byte
		if hasEther {
			// Prepend ethernet header: destMac + srcMac + etherType
			copy(scratch[0:6], destMac)
			copy(scratch[6:12], tx.MAC)
			copy(scratch[12:14], ipv4EtherType[:])
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

// createTransmitSocket creates and binds a send-only AF_PACKET raw socket for the
// named interface. The socket protocol is 0 (rather than ETH_P_ALL): these sockets
// are only ever written to, never read or polled, so binding them to ETH_P_ALL
// would needlessly install a kernel receive tap that clones every packet in and
// out of the interface into a queue that is never drained.
func createTransmitSocket(iface *InterfaceResult) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		return 0, fmt.Errorf("cannot create transmit socket for %s: %w", iface.Name, err)
	}
	sa := &unix.SockaddrLinklayer{
		Protocol: 0,
		Ifindex:  iface.Index,
	}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return 0, fmt.Errorf("cannot bind transmit socket to %s: %w", iface.Name, err)
	}
	return fd, nil
}

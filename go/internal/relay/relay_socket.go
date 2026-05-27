package relay

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

// AddListener sets up receive and transmit sockets for a relay address.
func (pr *PacketRelay) AddListener(addr string, port int, service string) error {
	addrN, err := netip.ParseAddr(addr)
	if err != nil {
		return fmt.Errorf("invalid relay address %q: %w", addr, err)
	}
	if IsBroadcast(addr) {
		pr.etherAddrs[addrN] = BroadcastIPToMAC()
	} else if IsMulticast(addr) {
		pr.etherAddrs[addrN] = MulticastIPToMAC(addr)
	} else {
		pr.etherAddrs[addrN] = nil
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

			bcastBytes := ifInfo.Broadcast.As4()
			sa := &unix.SockaddrInet4{Port: port, Addr: bcastBytes}
			if err := unix.Bind(fd, sa); err != nil {
				unix.Close(fd)
				return fmt.Errorf("cannot bind broadcast socket to %s:%d: %w", ifInfo.Broadcast, port, err)
			}
			pr.receivers = append(pr.receivers, Receiver{fd: fd})

		} else if IsMulticast(addr) {
			mcastIP := net.ParseIP(addr).To4()
			ifIPBytes := ifInfo.Addr.As4()
			mreq := &unix.IPMreq{}
			copy(mreq.Multiaddr[:], mcastIP)
			copy(mreq.Interface[:], ifIPBytes[:])
			if err := unix.SetsockoptIPMreq(multicastRxFd, unix.SOL_IP, unix.IP_ADD_MEMBERSHIP, mreq); err != nil {
				return fmt.Errorf("cannot join multicast group %s on %s: %w", addr, ifInfo.Name, err)
			}
		}

		// Create transmitter for this interface (unless in noTransmitInterfaces)
		if !pr.noTransmitInterfaces[iface] {
			txFd, err := createTransmitSocket(ifInfo.Name)
			if err != nil {
				return err
			}

			listenNetip := addrN
			if IsBroadcast(addr) {
				listenNetip = ifInfo.Broadcast
			}

			pr.transmitters = append(pr.transmitters, Transmitter{
				Relay:     RelayAddr{Addr: listenNetip, Port: port},
				Interface: ifInfo.Name,
				Addr:      ifInfo.Addr,
				MAC:       ifInfo.MAC,
				Network:   ifInfo.Network,
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

// InterfaceResult holds resolved interface information.
type InterfaceResult struct {
	Name      string
	MAC       net.HardwareAddr
	Addr      netip.Addr
	Network   netip.Prefix
	Broadcast netip.Addr
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
				MAC:       iface.HardwareAddr,
				Addr:      ifAddr,
				Network:   netip.PrefixFrom(ifAddr, ones).Masked(),
				Broadcast: netip.AddrFrom4(bcastBytes),
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
	if pr.wait && !result.Addr.IsValid() {
		for {
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

// recoverTransmitter attempts to re-create the transmit socket after ENXIO.
func (pr *PacketRelay) recoverTransmitter(tx *Transmitter, destMac net.HardwareAddr, ipHeaderLength int, data []byte) {
	pr.logger.Info("Attempting to recover interface %s", tx.Interface)
	ifInfo, err := pr.getInterface(tx.Interface)
	if err != nil {
		pr.logger.Warning("Recovery failed for %s: %s", tx.Interface, err)
		return
	}
	newFd, err := createTransmitSocket(ifInfo.Name)
	if err != nil {
		pr.logger.Warning("Recovery socket creation failed for %s: %s", tx.Interface, err)
		return
	}
	unix.Close(tx.Socket)
	tx.Socket = newFd
	tx.MAC = ifInfo.MAC
	tx.Network = ifInfo.Network
	tx.Addr = ifInfo.Addr
	if err := pr.transmitPacket(tx, destMac, ipHeaderLength, data); err != nil {
		pr.logger.Warning("Recovery retransmit failed for %s: %s", tx.Interface, err)
	}
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

	udpHeader = ComputeUDPChecksum(ipHeader, udpHeader, payload)

	hasEther := !bytes.Equal(tx.MAC, zeroMAC)

	// The IP payload is UDP header + UDP data. For fragmentation purposes,
	// we fragment the entire IP payload (transport header + data).
	ipPayload := make([]byte, 0, 8+len(payload))
	ipPayload = append(ipPayload, udpHeader...)
	ipPayload = append(ipPayload, payload...)

	// Get a scratch buffer large enough for the largest frame: 14 (ether) + IP header + max fragment
	maxFrameSize := 14 + ipHeaderLength + len(ipPayload)
	scratchBp := getBuffer(maxFrameSize)
	defer putBuffer(scratchBp)
	scratch := *scratchBp

	for boundary := 0; boundary < len(ipPayload); boundary += udpMaxLength {
		end := boundary + udpMaxLength
		if end > len(ipPayload) {
			end = len(ipPayload)
		}
		fragment := ipPayload[boundary:end]
		totalLength := ipHeaderLength + len(fragment)
		moreFragments := end < len(ipPayload)

		// Fragment offset is in 8-byte units per RFC 791
		flagsOffset := uint16((boundary / 8) & 0x1fff)
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

		// Append the fragment data (first fragment includes UDP header, subsequent don't)
		copy(scratch[etherOff+ipHeaderLength:], fragment)

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

// interfaceIndex returns the OS interface index for a named interface.
func interfaceIndex(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return iface.Index, nil
}

// createTransmitSocket creates and binds an AF_PACKET raw socket for the named interface.
func createTransmitSocket(ifName string) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, ethPAllBE)
	if err != nil {
		return 0, fmt.Errorf("cannot create transmit socket for %s: %w", ifName, err)
	}
	ifIndex, err := interfaceIndex(ifName)
	if err != nil {
		unix.Close(fd)
		return 0, fmt.Errorf("cannot get interface index for %s: %w", ifName, err)
	}
	sa := &unix.SockaddrLinklayer{
		Protocol: uint16(ethPAllBE),
		Ifindex:  ifIndex,
	}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return 0, fmt.Errorf("cannot bind transmit socket to %s: %w", ifName, err)
	}
	return fd, nil
}

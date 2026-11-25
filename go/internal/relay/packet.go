package relay

import (
	"encoding/binary"
	"net"
	"net/netip"
)

// Pre-parsed multicast range boundaries for fast comparison.
var (
	multicastMin = netip.MustParseAddr("224.0.0.0")
	multicastMax = netip.MustParseAddr("239.255.255.255")
	broadcastIP  = netip.MustParseAddr("255.255.255.255")
)

// NetChecksum computes the one's complement checksum over data, used for IP and UDP checksums.
func NetChecksum(data []byte) uint16 {
	length := len(data)
	var sum uint32
	for i := 0; i+1 < length; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if length%2 != 0 {
		sum += uint32(data[length-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// checksumAdd accumulates a running one's complement sum over data.
func checksumAdd(sum uint32, data []byte) uint32 {
	length := len(data)
	for i := 0; i+1 < length; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if length%2 != 0 {
		sum += uint32(data[length-1]) << 8
	}
	return sum
}

// checksumFinalize folds a 32-bit sum into a 16-bit one's complement checksum.
func checksumFinalize(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ComputeIPChecksum zeros out the existing checksum field and recomputes the IP header checksum.
// Modifies data in place and returns the same slice.
func ComputeIPChecksum(data []byte, ipHeaderLength int) []byte {
	if ipHeaderLength < 12 || len(data) < ipHeaderLength {
		return data
	}
	data[10] = 0
	data[11] = 0
	checksum := NetChecksum(data[:ipHeaderLength])
	binary.BigEndian.PutUint16(data[10:12], checksum)
	return data
}

// udpChecksumValue computes the UDP checksum value over the pseudo-header, UDP
// header, and data without concatenation. Per RFC 768, a computed checksum of
// zero is transmitted as all-ones (0xFFFF), since an on-wire 0x0000 signals
// "checksum not computed."
func udpChecksumValue(ipHeader, udpHeader, data []byte) uint16 {
	var sum uint32
	sum = checksumAdd(sum, ipHeader[12:20])                // src + dst IP
	sum += uint32(ipHeader[9])                             // protocol
	sum += uint32(binary.BigEndian.Uint16(udpHeader[4:6])) // udp length

	sum = checksumAdd(sum, udpHeader[:6]) // src port, dst port, length
	sum = checksumAdd(sum, data)

	checksum := checksumFinalize(sum)
	if checksum == 0 {
		checksum = 0xffff
	}
	return checksum
}

// ComputeUDPChecksum computes the UDP checksum using the pseudo-header and
// returns a fresh 8-byte UDP header with the checksum field set.
func ComputeUDPChecksum(ipHeader, udpHeader, data []byte) []byte {
	if len(ipHeader) < 20 || len(udpHeader) < 8 {
		return udpHeader
	}
	checksum := udpChecksumValue(ipHeader, udpHeader, data)

	result := make([]byte, 8)
	copy(result, udpHeader[:6])
	binary.BigEndian.PutUint16(result[6:8], checksum)
	return result
}

// copyIPPayloadRange copies the [start:end) byte range of the virtual
// concatenation (udpHeader ++ payload) into dst. udpHeader is 8 bytes; bytes at
// virtual offset < 8 come from udpHeader, the rest from payload. Used to build
// IP fragments without materializing the full IP payload in a heap buffer.
func copyIPPayloadRange(dst, udpHeader, payload []byte, start, end int) {
	n := 0
	if start < len(udpHeader) {
		hEnd := end
		if hEnd > len(udpHeader) {
			hEnd = len(udpHeader)
		}
		n += copy(dst[n:], udpHeader[start:hEnd])
	}
	pStart := start - len(udpHeader)
	if pStart < 0 {
		pStart = 0
	}
	pEnd := end - len(udpHeader)
	if pEnd > pStart {
		copy(dst[n:], payload[pStart:pEnd])
	}
}

// ModifyUDPPacket modifies the source/destination address and port of a UDP packet.
// Pass netip.Addr{} or 0 to leave the corresponding field unchanged.
func ModifyUDPPacket(data []byte, ipHeaderLength int, newSrc netip.Addr, newSrcPort uint16, newDst netip.Addr, newDstPort uint16) []byte {
	if ipHeaderLength < 20 || len(data) < ipHeaderLength+8 {
		return data
	}
	srcAddrBytes := [4]byte{data[12], data[13], data[14], data[15]}
	dstAddrBytes := [4]byte{data[16], data[17], data[18], data[19]}
	srcPort := binary.BigEndian.Uint16(data[ipHeaderLength : ipHeaderLength+2])
	dstPort := binary.BigEndian.Uint16(data[ipHeaderLength+2 : ipHeaderLength+4])

	if newSrc.IsValid() {
		srcAddrBytes = newSrc.As4()
	}
	if newDst.IsValid() {
		dstAddrBytes = newDst.As4()
	}
	if newSrcPort != 0 {
		srcPort = newSrcPort
	}
	if newDstPort != 0 {
		dstPort = newDstPort
	}

	// Build IP header: bytes 0-11 (version/IHL/TOS/len/id/flags/TTL/proto/checksum),
	// then src+dst at fixed offsets 12-19, then any IP options (byte 20+).
	ipHeader := make([]byte, 0, ipHeaderLength)
	ipHeader = append(ipHeader, data[:12]...)
	ipHeader = append(ipHeader, srcAddrBytes[:]...)
	ipHeader = append(ipHeader, dstAddrBytes[:]...)
	if ipHeaderLength > 20 {
		ipHeader = append(ipHeader, data[20:ipHeaderLength]...)
	}

	udpData := data[ipHeaderLength+8:]
	udpLength := uint16(8 + len(udpData))
	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(udpHeader[2:4], dstPort)
	binary.BigEndian.PutUint16(udpHeader[4:6], udpLength)
	binary.BigEndian.PutUint16(udpHeader[6:8], 0)

	fullPacket := make([]byte, 0, len(ipHeader)+len(udpHeader)+len(udpData))
	fullPacket = append(fullPacket, ipHeader...)
	fullPacket = append(fullPacket, udpHeader...)
	fullPacket = append(fullPacket, udpData...)

	ComputeIPChecksum(fullPacket, ipHeaderLength)

	newUDPHeader := ComputeUDPChecksum(fullPacket[:ipHeaderLength], fullPacket[ipHeaderLength:ipHeaderLength+8], udpData)

	copy(fullPacket[ipHeaderLength:ipHeaderLength+8], newUDPHeader)
	return fullPacket
}

// MdnsSetUnicastBit sets the UNICAST-RESPONSE bit in mDNS query packets.
func MdnsSetUnicastBit(data []byte, ipHeaderLength int) []byte {
	udpDataStart := ipHeaderLength + 8
	// Require the full 12-byte DNS header: flags at [2:4], question count at
	// [4:6], and the label loop below begins at offset 12. A shorter guard
	// (e.g. +4) lets a 4- or 5-byte payload reach the udpData[4:6] read and
	// panic, which would crash the relay on a crafted mDNS packet.
	if len(data) < udpDataStart+12 {
		return data
	}
	flags := binary.BigEndian.Uint16(data[udpDataStart+2 : udpDataStart+4])
	if flags&0x8000 != 0 {
		return data
	}

	headers := data[:udpDataStart]
	udpData := make([]byte, len(data[udpDataStart:]))
	copy(udpData, data[udpDataStart:])

	queries := binary.BigEndian.Uint16(udpData[4:6])

	queryCount := uint16(0)
	ptr := 12
	for {
		if ptr >= len(udpData) {
			break
		}
		labelLength := udpData[ptr]
		if labelLength&0x3f == 0 {
			if labelLength&0xc0 != 0 {
				ptr++
			}
			queryCount++
			if ptr+5 <= len(udpData) {
				classField := binary.BigEndian.Uint16(udpData[ptr+3 : ptr+5])
				binary.BigEndian.PutUint16(udpData[ptr+3:ptr+5], classField|0x8000)
			}
			if queryCount == queries {
				break
			}
			ptr += 5
		} else {
			ptr += int(labelLength) + 1
		}
	}

	result := make([]byte, 0, len(headers)+len(udpData))
	result = append(result, headers...)
	result = append(result, udpData...)
	return result
}

// IsMulticast returns true if the IP address is a multicast address (224.0.0.0 - 239.255.255.255).
func IsMulticast(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return addr.Compare(multicastMin) >= 0 && addr.Compare(multicastMax) <= 0
}

// IsBroadcast returns true if the IP is the broadcast address 255.255.255.255.
func IsBroadcast(ip string) bool {
	return ip == BroadcastAddr
}

// MulticastIPToMAC derives the ethernet MAC from a multicast IP address per RFC 1112.
func MulticastIPToMAC(ip string) net.HardwareAddr {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return nil
	}
	b := addr.As4()
	return net.HardwareAddr{0x01, 0x00, 0x5e, b[1] & 0x7f, b[2], b[3]}
}

// BroadcastIPToMAC returns the broadcast ethernet MAC (ff:ff:ff:ff:ff:ff).
func BroadcastIPToMAC() net.HardwareAddr {
	return net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
}

// IP2Long converts a dotted-quad IP string to a uint32.
func IP2Long(ip string) uint32 {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return 0
	}
	b := addr.As4()
	return binary.BigEndian.Uint32(b[:])
}

// Long2IP converts a uint32 to a dotted-quad IP string.
func Long2IP(ip uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ip)
	return netip.AddrFrom4(b).String()
}

// OnNetwork checks if an IP address is within a network prefix.
func OnNetwork(ip netip.Addr, network netip.Prefix) bool {
	return network.Contains(ip)
}

// OnNetworkPrefix checks if an IP address is within a netip.Prefix.
func OnNetworkPrefix(ip netip.Addr, prefix netip.Prefix) bool {
	return prefix.Contains(ip)
}

// CIDRToNetmask converts CIDR prefix bits to a dotted-quad netmask string.
func CIDRToNetmask(bits int) string {
	mask := uint32(0xffffffff) << (32 - bits) & 0xffffffff
	return Long2IP(mask)
}

// AddrFrom4Bytes creates a netip.Addr from 4 raw bytes (no heap allocation).
func AddrFrom4Bytes(b []byte) netip.Addr {
	return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]})
}

// UnicastIPToMAC looks up a MAC address in the ARP table for a given IP.
// If procNetArp is non-empty, it is used instead of reading /proc/net/arp.
func UnicastIPToMAC(ip string, procNetArp string) (string, error) {
	if procNetArp == "" {
		data, err := readFile("/proc/net/arp")
		if err != nil {
			return "", err
		}
		procNetArp = string(data)
	}
	return parseARPTable(procNetArp, ip), nil
}

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
	data[10] = 0
	data[11] = 0
	checksum := NetChecksum(data[:ipHeaderLength])
	binary.BigEndian.PutUint16(data[10:12], checksum)
	return data
}

// ComputeUDPChecksum computes the UDP checksum using the pseudo-header.
// Computes incrementally across pseudo-header, UDP header, and data without concatenation.
func ComputeUDPChecksum(ipHeader, udpHeader, data []byte) []byte {
	var sum uint32
	sum = checksumAdd(sum, ipHeader[12:20])                // src + dst IP
	sum += uint32(ipHeader[9])                             // protocol
	sum += uint32(binary.BigEndian.Uint16(udpHeader[4:6])) // udp length

	sum = checksumAdd(sum, udpHeader[:6]) // src port, dst port, length
	sum = checksumAdd(sum, data)

	checksum := checksumFinalize(sum)

	result := make([]byte, 8)
	copy(result, udpHeader[:6])
	binary.BigEndian.PutUint16(result[6:8], checksum)
	return result
}

// ModifyUDPPacket modifies the source/destination address and port of a UDP packet.
// Pass empty string or 0 to leave the corresponding field unchanged.
func ModifyUDPPacket(data []byte, ipHeaderLength int, newSrcAddr string, newSrcPort uint16, newDstAddr string, newDstPort uint16) []byte {
	srcAddr := net.IP(data[12:16]).To4()
	dstAddr := net.IP(data[16:20]).To4()
	srcPort := binary.BigEndian.Uint16(data[ipHeaderLength : ipHeaderLength+2])
	dstPort := binary.BigEndian.Uint16(data[ipHeaderLength+2 : ipHeaderLength+4])

	if newSrcAddr != "" {
		srcAddr = net.ParseIP(newSrcAddr).To4()
	}
	if newDstAddr != "" {
		dstAddr = net.ParseIP(newDstAddr).To4()
	}
	if newSrcPort != 0 {
		srcPort = newSrcPort
	}
	if newDstPort != 0 {
		dstPort = newDstPort
	}

	ipHeader := make([]byte, 0, ipHeaderLength)
	ipHeader = append(ipHeader, data[:ipHeaderLength-8]...)
	ipHeader = append(ipHeader, srcAddr...)
	ipHeader = append(ipHeader, dstAddr...)

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

	result := make([]byte, 0, len(fullPacket))
	result = append(result, fullPacket[:ipHeaderLength]...)
	result = append(result, newUDPHeader...)
	result = append(result, udpData...)

	return result
}

// MdnsSetUnicastBit sets the UNICAST-RESPONSE bit in mDNS query packets.
func MdnsSetUnicastBit(data []byte, ipHeaderLength int) []byte {
	headers := data[:ipHeaderLength+8]
	udpData := make([]byte, len(data[ipHeaderLength+8:]))
	copy(udpData, data[ipHeaderLength+8:])

	flags := binary.BigEndian.Uint16(udpData[2:4])
	if flags&0x8000 != 0 {
		result := make([]byte, 0, len(data))
		result = append(result, headers...)
		result = append(result, udpData...)
		return result
	}

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

// OnNetwork checks if an IP is on the given network/netmask (string-based API for backward compat).
func OnNetwork(ip, network, netmask string) bool {
	ipL := IP2Long(ip)
	networkL := IP2Long(network)
	netmaskL := IP2Long(netmask)
	return (ipL & netmaskL) == (networkL & netmaskL)
}

// OnNetworkPrefix checks if an IP address is within a netip.Prefix.
func OnNetworkPrefix(ip string, prefix netip.Prefix) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return prefix.Contains(addr)
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

package relay

import (
	"encoding/binary"
	"net"
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

// ComputeIPChecksum zeros out the existing checksum field and recomputes the IP header checksum.
// Returns the updated packet with the new checksum in bytes 10-11.
func ComputeIPChecksum(data []byte, ipHeaderLength int) []byte {
	// Zero out existing checksum
	result := make([]byte, len(data))
	copy(result, data)
	result[10] = 0
	result[11] = 0

	checksum := NetChecksum(result[:ipHeaderLength])
	binary.BigEndian.PutUint16(result[10:12], checksum)
	return result
}

// ComputeUDPChecksum computes the UDP checksum using the pseudo-header.
func ComputeUDPChecksum(ipHeader, udpHeader, data []byte) []byte {
	// Pseudo IP header: src_ip(4) + dst_ip(4) + 0x00 + protocol(1) + udp_length(2)
	pseudoHeader := make([]byte, 0, 12)
	pseudoHeader = append(pseudoHeader, ipHeader[12:20]...) // src + dst IP
	pseudoHeader = append(pseudoHeader, 0x00)               // zero
	pseudoHeader = append(pseudoHeader, ipHeader[9])         // protocol
	pseudoHeader = append(pseudoHeader, udpHeader[4:6]...)   // udp length

	// Build the full packet for checksum: pseudo + udp header (with zeroed checksum) + data
	packet := make([]byte, 0, len(pseudoHeader)+6+2+len(data))
	packet = append(packet, pseudoHeader...)
	packet = append(packet, udpHeader[:6]...) // src port, dst port, length
	packet = append(packet, 0x00, 0x00)       // zeroed checksum
	packet = append(packet, data...)

	// Pad to even length
	if len(packet)%2 != 0 {
		packet = append(packet, 0x00)
	}

	checksum := NetChecksum(packet)

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

	// Rebuild IP header (everything before the last 8 bytes which are src+dst IP)
	ipHeader := make([]byte, 0, ipHeaderLength)
	ipHeader = append(ipHeader, data[:ipHeaderLength-8]...)
	ipHeader = append(ipHeader, srcAddr...)
	ipHeader = append(ipHeader, dstAddr...)

	// Rebuild UDP header
	udpData := data[ipHeaderLength+8:]
	udpLength := uint16(8 + len(udpData))
	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(udpHeader[2:4], dstPort)
	binary.BigEndian.PutUint16(udpHeader[4:6], udpLength)
	binary.BigEndian.PutUint16(udpHeader[6:8], 0) // checksum zeroed, recomputed later

	// Recompute IP checksum
	fullPacket := make([]byte, 0, len(ipHeader)+len(udpHeader)+len(udpData))
	fullPacket = append(fullPacket, ipHeader...)
	fullPacket = append(fullPacket, udpHeader...)
	fullPacket = append(fullPacket, udpData...)

	fullPacket = ComputeIPChecksum(fullPacket, ipHeaderLength)

	// Recompute UDP checksum
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
		// Already set
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
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return false
	}
	return parsed[0] >= 224 && parsed[0] <= 239
}

// IsBroadcast returns true if the IP is the broadcast address 255.255.255.255.
func IsBroadcast(ip string) bool {
	return ip == BroadcastAddr
}

// MulticastIPToMAC derives the ethernet MAC from a multicast IP address per RFC 1112.
func MulticastIPToMAC(ip string) net.HardwareAddr {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return nil
	}
	mac := make(net.HardwareAddr, 6)
	mac[0] = 0x01
	mac[1] = 0x00
	mac[2] = 0x5e
	mac[3] = parsed[1] & 0x7f
	mac[4] = parsed[2]
	mac[5] = parsed[3]
	return mac
}

// BroadcastIPToMAC returns the broadcast ethernet MAC (ff:ff:ff:ff:ff:ff).
func BroadcastIPToMAC() net.HardwareAddr {
	return net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
}

// IP2Long converts a dotted-quad IP string to a uint32.
func IP2Long(ip string) uint32 {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return 0
	}
	return binary.BigEndian.Uint32(parsed)
}

// Long2IP converts a uint32 to a dotted-quad IP string.
func Long2IP(ip uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, ip)
	return net.IP(b).String()
}

// OnNetwork checks if an IP is on the given network/netmask.
func OnNetwork(ip, network, netmask string) bool {
	ipL := IP2Long(ip)
	networkL := IP2Long(network)
	netmaskL := IP2Long(netmask)
	return (ipL & netmaskL) == (networkL & netmaskL)
}

// CIDRToNetmask converts CIDR prefix bits to a dotted-quad netmask string.
func CIDRToNetmask(bits int) string {
	mask := uint32(0xffffffff) << (32 - bits) & 0xffffffff
	return Long2IP(mask)
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

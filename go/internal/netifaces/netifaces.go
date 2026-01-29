// Package netifaces provides network interface enumeration, similar to the
// Python netifaces package.
package netifaces

import (
	"encoding/binary"
	"fmt"
	"net"
)

// InterfaceInfo holds the network information for a single interface.
type InterfaceInfo struct {
	Name      string
	MAC       net.HardwareAddr
	IP        net.IP
	Netmask   net.IPMask
	Broadcast net.IP
}

// Interfaces returns information about all IPv4-capable network interfaces.
func Interfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}

	var result []InterfaceInfo
	for _, iface := range ifaces {
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

			broadcast := computeBroadcast(ip4, ipnet.Mask)
			result = append(result, InterfaceInfo{
				Name:      iface.Name,
				MAC:       iface.HardwareAddr,
				IP:        ip4,
				Netmask:   ipnet.Mask,
				Broadcast: broadcast,
			})
		}
	}

	return result, nil
}

// FindByName finds an interface by its OS name (e.g. "eth0").
func FindByName(name string) (*InterfaceInfo, error) {
	ifaces, err := Interfaces()
	if err != nil {
		return nil, err
	}
	for _, info := range ifaces {
		if info.Name == name {
			return &info, nil
		}
	}
	return nil, fmt.Errorf("interface %s not found", name)
}

// FindByIP finds an interface by its IPv4 address.
func FindByIP(ip string) (*InterfaceInfo, error) {
	ifaces, err := Interfaces()
	if err != nil {
		return nil, err
	}
	for _, info := range ifaces {
		if info.IP.String() == ip {
			return &info, nil
		}
	}
	return nil, fmt.Errorf("interface with IP %s not found", ip)
}

// FindByCIDR finds an interface whose IP falls within the given CIDR block.
func FindByCIDR(cidr string) (*InterfaceInfo, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %s: %w", cidr, err)
	}
	ifaces, err := Interfaces()
	if err != nil {
		return nil, err
	}
	for _, info := range ifaces {
		if network.Contains(info.IP) {
			return &info, nil
		}
	}
	return nil, fmt.Errorf("no interface found in network %s", cidr)
}

func computeBroadcast(ip net.IP, mask net.IPMask) net.IP {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	// Ensure mask is 4 bytes
	if len(mask) == 16 {
		mask = mask[12:]
	}
	ipInt := binary.BigEndian.Uint32(ip4)
	maskInt := binary.BigEndian.Uint32(mask)
	bcast := ipInt | ^maskInt
	result := make(net.IP, 4)
	binary.BigEndian.PutUint32(result, bcast)
	return result
}

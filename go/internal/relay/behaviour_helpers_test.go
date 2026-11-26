package relay

import "net/netip"

// These adapt the behaviour tests to the relay's internals.

func deliver(pr *PacketRelay, packet []byte, sender netip.Addr, from string) {
	pr.processPacket(packet, sender, from, nil)
}

// listenOn records the transmitters' networks as listed interfaces.
func listenOn(pr *PacketRelay, txs ...Transmitter) {
	for _, tx := range txs {
		pr.listed = append(pr.listed, listedInterface{spec: tx.Interface, info: InterfaceResult{
			Name: tx.Interface, Addr: tx.Addr, Network: tx.Network, Broadcast: tx.Broadcast,
		}})
	}
}

// addRule records a relayed address and port.
func addRule(pr *PacketRelay, addr string, port int) {
	pr.relays = append(pr.relays, relayRule{addr: netip.MustParseAddr(addr), port: port})
}

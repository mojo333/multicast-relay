// multicast-relay reimplemented in Go.
//
// Al Smith <ajs@aeschi.eu> January 2018
// Go port 2026
// https://github.com/mojo333/multicast-relay
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mojo333/multicast-relay/internal/logger"
	"github.com/mojo333/multicast-relay/internal/relay"
)

// stringSlice implements flag.Value for repeatable string flags.
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ", ") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	os.Exit(run())
}

func run() int {
	var interfaces stringSlice
	var noTransmitInterfaces stringSlice
	var masquerade stringSlice
	var relayAddrs stringSlice
	var listenAddrs stringSlice
	var remoteAddrs stringSlice

	flag.Var(&interfaces, "interfaces", "Relay between these interfaces (specify multiple times or space-separated).")
	flag.Var(&noTransmitInterfaces, "noTransmitInterfaces", "Do not relay packets via these interfaces, listen only.")
	ifFilter := flag.String("ifFilter", "", "JSON file specifying which interface(s) a particular source IP can relay to.")
	ssdpUnicastAddr := flag.String("ssdpUnicastAddr", "", "IP address to listen to SSDP unicast replies.")
	oneInterface := flag.Bool("oneInterface", false, "Only one interface exists, connected to two networks.")
	flag.Var(&relayAddrs, "relay", "Relay additional multicast/broadcast address(es) in A.B.C.D:PORT format.")
	noMDNS := flag.Bool("noMDNS", false, "Do not relay mDNS packets.")
	mdnsForceUnicast := flag.Bool("mdnsForceUnicast", false, "Force mDNS packets to have the UNICAST-RESPONSE bit set.")
	noSSDP := flag.Bool("noSSDP", false, "Do not relay SSDP packets.")
	noSonosDiscovery := flag.Bool("noSonosDiscovery", false, "Do not relay broadcast Sonos discovery packets.")
	allowNonEther := flag.Bool("allowNonEther", false, "Allow non-ethernet interfaces to be configured.")
	flag.Var(&masquerade, "masquerade", "Masquerade outbound packets from these interface(s).")
	waitForIP := flag.Bool("wait", false, "Wait for IPv4 address assignment.")
	ttl := flag.Int("ttl", 0, "Set TTL on outbound packets (1-255).")
	flag.Var(&listenAddrs, "listen", "Listen for remote connections from these addresses.")
	flag.Var(&remoteAddrs, "remote", "Relay packets to remote multicast-relay(s).")
	remotePort := flag.Int("remotePort", 1900, "Port for remote relay communications.")
	remoteRetry := flag.Int("remoteRetry", 5, "Retry interval (seconds) for failed remote connections.")
	noRemoteRelay := flag.Bool("noRemoteRelay", false, "Only relay on local interfaces.")
	aesKey := flag.String("aes", "", "AES encryption key for remote relay connections.")
	foreground := flag.Bool("foreground", false, "Do not background, log to stdout.")
	logfile := flag.String("logfile", "", "Save logs to this file.")
	verbose := flag.Bool("verbose", false, "Enable verbose output.")

	// Parse with support for space-separated values after a single flag
	flag.Parse()

	// Collect remaining args as additional interfaces (for compatibility: --interfaces eth0 eth1)
	// Go's flag package doesn't natively support nargs='+', so we handle trailing args.
	if flag.NArg() > 0 {
		interfaces = append(interfaces, flag.Args()...)
	}

	if len(interfaces) < 2 && !*oneInterface && len(listenAddrs) == 0 && len(remoteAddrs) == 0 {
		fmt.Println("You should specify at least two interfaces to relay between")
		return 1
	}

	if len(remoteAddrs) > 0 && len(listenAddrs) > 0 {
		fmt.Println("Relay role should be either --listen or --remote (or neither) but not both")
		return 1
	}

	if *ttl != 0 && (*ttl < 1 || *ttl > 255) {
		fmt.Println("Invalid TTL (must be between 1 and 255)")
		return 1
	}

	// Daemonize if not foreground
	if !*foreground {
		// In Go we don't fork; instead we just detach stdin.
		// For true daemonization, use systemd or similar.
		os.Stdin.Close()
	}

	log, err := logger.New(*foreground, *logfile, *verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing logger: %s\n", err)
		return 1
	}

	// Build relay set
	type relayEntry struct {
		addrPort string
		service  string
	}
	relaySet := map[string]relayEntry{}

	if !*noMDNS {
		key := fmt.Sprintf("%s:%d", relay.MDNSMcastAddr, relay.MDNSMcastPort)
		relaySet[key] = relayEntry{key, "mDNS"}
	}
	if !*noSSDP {
		key := fmt.Sprintf("%s:%d", relay.SSDPMcastAddr, relay.SSDPMcastPort)
		relaySet[key] = relayEntry{key, "SSDP"}
	}
	if !*noSonosDiscovery {
		key := relay.BroadcastAddr + ":6969"
		relaySet[key] = relayEntry{key, "Sonos Setup Discovery"}
	}
	if *ssdpUnicastAddr != "" {
		key := fmt.Sprintf("%s:%d", *ssdpUnicastAddr, relay.SSDPUnicastPort)
		relaySet[key] = relayEntry{key, "SSDP Unicast"}
	}
	for _, r := range relayAddrs {
		relaySet[r] = relayEntry{r, ""}
	}

	cfg := relay.Config{
		Interfaces:           interfaces,
		NoTransmitInterfaces: noTransmitInterfaces,
		IfFilter:             *ifFilter,
		WaitForIP:            *waitForIP,
		TTL:                  *ttl,
		OneInterface:         *oneInterface,
		AllowNonEther:        *allowNonEther,
		SSDPUnicastAddr:      *ssdpUnicastAddr,
		MDNSForceUnicast:     *mdnsForceUnicast,
		Masquerade:           masquerade,
		Listen:               listenAddrs,
		Remote:               remoteAddrs,
		RemotePort:           *remotePort,
		RemoteRetry:          *remoteRetry,
		NoRemoteRelay:        *noRemoteRelay,
		AESKey:               *aesKey,
		Logger:               log,
	}

	packetRelay, err := relay.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing relay: %s\n", err)
		return 1
	}

	// Add listeners for each relay address
	for _, entry := range relaySet {
		parts := strings.SplitN(entry.addrPort, ":", 2)
		if len(parts) != 2 {
			msg := fmt.Sprintf("%s: Expecting A.B.C.D:P format", entry.addrPort)
			if *foreground {
				fmt.Println(msg)
			} else {
				log.Warning("%s", msg)
			}
			return 1
		}
		addr := parts[0]
		var port int
		if _, err := fmt.Sscanf(parts[1], "%d", &port); err != nil {
			msg := fmt.Sprintf("%s: Invalid port number", entry.addrPort)
			if *foreground {
				fmt.Println(msg)
			} else {
				log.Warning("%s", msg)
			}
			return 1
		}

		// Validate address type
		var relayType string
		if relay.IsMulticast(addr) {
			relayType = "multicast"
		} else if relay.IsBroadcast(addr) {
			relayType = "broadcast"
		} else if *ssdpUnicastAddr != "" {
			relayType = "unicast"
		} else {
			msg := fmt.Sprintf("IP address %s is neither a multicast nor a broadcast address", addr)
			if *foreground {
				fmt.Println(msg)
			} else {
				log.Warning("%s", msg)
			}
			return 1
		}

		if port < 0 || port > 65535 {
			msg := fmt.Sprintf("UDP port %d out of range", port)
			if *foreground {
				fmt.Println(msg)
			} else {
				log.Warning("%s", msg)
			}
			return 1
		}

		serviceSuffix := ""
		if entry.service != "" {
			serviceSuffix = fmt.Sprintf(" (%s)", entry.service)
		}
		log.Info("Adding %s relay for %s:%d%s", relayType, addr, port, serviceSuffix)

		if err := packetRelay.AddListener(addr, port, entry.service); err != nil {
			fmt.Fprintf(os.Stderr, "Error adding listener for %s:%d: %s\n", addr, port, err)
			return 1
		}
	}

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		os.Exit(0)
	}()

	if err := packetRelay.Loop(); err != nil {
		fmt.Fprintf(os.Stderr, "Relay error: %s\n", err)
		return 1
	}

	return 0
}

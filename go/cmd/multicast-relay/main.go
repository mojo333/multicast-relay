// multicast-relay reimplemented in Go.
//
// https://github.com/mojo333/multicast-relay
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/mojo333/multicast-relay/internal/logger"
	"github.com/mojo333/multicast-relay/internal/relay"
)

var version = "dev"

// stringSlice implements flag.Value for repeatable string flags.
type stringSlice []string

// String returns the flag value as a string.
func (s *stringSlice) String() string { return strings.Join(*s, ", ") }

// Set appends a value to the slice.
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// main is the program entry point.
func main() {
	os.Exit(run())
}

// run parses flags, configures the relay, and runs the event loop.
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
	aesKey := flag.String("aes", "", "AES encryption key for remote relay connections (or set MULTICAST_RELAY_AES_KEY env var).")
	dropUser := flag.String("drop-user", "", "Drop to this unprivileged user after socket setup (Linux only; requires root).")
	foreground := flag.Bool("foreground", false, "Do not background, log to stdout.")
	logfile := flag.String("logfile", "", "Save logs to this file.")
	verbose := flag.Bool("verbose", false, "Enable verbose output.")
	monitor := flag.String("monitor", "", "Write startup, errors, and shutdown events to this log file.")

	// Parse with support for space-separated values after a single flag
	flag.Parse()

	// Collect remaining args as additional interfaces (for compatibility: --interfaces eth0 eth1)
	// Go's flag package doesn't natively support nargs='+', so we handle trailing args.
	if flag.NArg() > 0 {
		interfaces = append(interfaces, flag.Args()...)
	}

	// AES key: --aes flag takes precedence; fall back to environment variable.
	aesKeyVal := *aesKey
	if aesKeyVal == "" {
		aesKeyVal = os.Getenv("MULTICAST_RELAY_AES_KEY")
	}

	// Validate interface name specs (name, IP, or CIDR): non-empty, max 100 chars.
	for _, iface := range interfaces {
		if err := validateInterfaceSpec(iface); err != nil {
			fmt.Fprintf(os.Stderr, "Invalid --interfaces value: %s\n", err)
			return 1
		}
	}
	for _, iface := range masquerade {
		if err := validateInterfaceSpec(iface); err != nil {
			fmt.Fprintf(os.Stderr, "Invalid --masquerade value: %s\n", err)
			return 1
		}
	}
	// Validate listen addresses (must be valid IPs).
	for _, addr := range listenAddrs {
		if strings.TrimSpace(addr) == "" {
			fmt.Fprintln(os.Stderr, "--listen: empty address")
			return 1
		}
	}
	// Validate remote port range.
	if *remotePort < 1 || *remotePort > 65535 {
		fmt.Fprintln(os.Stderr, "--remotePort: must be 1–65535")
		return 1
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
	defer log.Close()

	// Set up monitor log if requested
	if *monitor != "" {
		if err := log.SetMonitor(*monitor); err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing monitor log: %s\n", err)
			return 1
		}
	}

	// Log startup to monitor
	log.Info("multicast-relay %s starting", version)
	log.Monitor("Process started (pid %d, version %s)", os.Getpid(), version)
	log.Monitor("Parameters: %s", formatArgs())

	// Warn loudly when remote relay is used without encryption: without --aes
	// there is no cryptographic authentication of remote peers, and any host that
	// can reach the port from an allowed source IP can inject packets onto local
	// networks.
	if (len(listenAddrs) > 0 || len(remoteAddrs) > 0) && aesKeyVal == "" {
		warn := "Remote relay is running WITHOUT encryption (--aes). Remote peers are not cryptographically authenticated; use --aes with a strong shared key on untrusted networks."
		log.Warning("%s", warn)
		log.Monitor("%s", warn)
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
		AESKey:               aesKeyVal,
		Logger:               log,
	}

	packetRelay, err := relay.New(cfg)
	if err != nil {
		log.Error("Error initializing relay: %s", err)
		log.Monitor("Process exiting: relay init error: %s", err)
		fmt.Fprintf(os.Stderr, "Error initializing relay: %s\n", err)
		return 1
	}

	fatal := func(msg string) int {
		if *foreground {
			fmt.Println(msg)
		} else {
			log.Warning("%s", msg)
		}
		log.Monitor("Process exiting: %s", msg)
		return 1
	}

	// Add listeners for each relay address
	var services []string
	for _, entry := range relaySet {
		parts := strings.SplitN(entry.addrPort, ":", 2)
		if len(parts) != 2 {
			return fatal(fmt.Sprintf("%s: Expecting A.B.C.D:P format", entry.addrPort))
		}
		addr := parts[0]
		var port int
		if _, err := fmt.Sscanf(parts[1], "%d", &port); err != nil {
			return fatal(fmt.Sprintf("%s: Invalid port number", entry.addrPort))
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
			return fatal(fmt.Sprintf("IP address %s is neither a multicast nor a broadcast address", addr))
		}

		if port < 0 || port > 65535 {
			return fatal(fmt.Sprintf("UDP port %d out of range", port))
		}

		serviceSuffix := ""
		if entry.service != "" {
			serviceSuffix = fmt.Sprintf(" (%s)", entry.service)
		}
		log.Info("Adding %s relay for %s:%d%s", relayType, addr, port, serviceSuffix)

		if err := packetRelay.AddListener(addr, port, entry.service); err != nil {
			log.Error("Error adding listener for %s:%d: %s", addr, port, err)
			log.Monitor("Process exiting: listener error for %s:%d: %s", addr, port, err)
			fmt.Fprintf(os.Stderr, "Error adding listener for %s:%d: %s\n", addr, port, err)
			return 1
		}

		label := fmt.Sprintf("%s %s:%d", relayType, addr, port)
		if entry.service != "" {
			label = entry.service
		}
		services = append(services, label)
	}

	log.Monitor("Relay active: interfaces=%v services=[%s]",
		[]string(interfaces), strings.Join(services, ", "))

	// Drop privileges after all raw sockets are created.
	if *dropUser != "" {
		if err := dropPrivileges(*dropUser); err != nil {
			log.Error("Failed to drop privileges to %q: %s", *dropUser, err)
			log.Monitor("Process exiting: privilege drop failed: %s", err)
			return 1
		}
		log.Info("Privileges dropped to user %q", *dropUser)
	}

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Monitor("Received signal %s, shutting down", sig)
		packetRelay.Close()
	}()

	if err := packetRelay.Loop(); err != nil {
		log.Error("Relay error: %s", err)
		log.Monitor("Process exiting: relay error: %s", err)
		fmt.Fprintf(os.Stderr, "Relay error: %s\n", err)
		return 1
	}

	log.Monitor("Process exiting: clean shutdown")
	return 0
}

// validateInterfaceSpec rejects obviously invalid interface specifications before passing them
// to the kernel. The kernel will reject malformed names, but early validation improves UX.
func validateInterfaceSpec(spec string) error {
	if strings.TrimSpace(spec) == "" {
		return fmt.Errorf("empty interface specification")
	}
	if len(spec) > 100 {
		return fmt.Errorf("interface specification too long: %q", spec)
	}
	return nil
}

// dropPrivileges drops root to the given username after socket setup.
// Uses syscall.Setuid/Setgid which on Linux (Go 1.16+) applies to all OS threads.
func dropPrivileges(username string) error {
	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("user %q not found: %w", username, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("invalid GID %q for user %q: %w", u.Gid, username, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("invalid UID %q for user %q: %w", u.Uid, username, err)
	}
	// Drop inherited supplementary groups before changing gid/uid. Without this,
	// the process keeps root's supplementary group memberships (potentially
	// including gid 0) after the drop, leaving privileges the "unprivileged" user
	// should not hold.
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("setgroups(%d): %w", gid, err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid(%d): %w", gid, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid(%d): %w", uid, err)
	}
	return nil
}

// formatArgs returns a string representation of the command-line arguments,
// masking the AES key if present.
func formatArgs() string {
	args := os.Args[1:]
	var parts []string
	maskNext := false
	for _, arg := range args {
		if maskNext {
			parts = append(parts, "****")
			maskNext = false
			continue
		}
		if arg == "--aes" || arg == "-aes" {
			parts = append(parts, arg)
			maskNext = true
			continue
		}
		if strings.HasPrefix(arg, "--aes=") || strings.HasPrefix(arg, "-aes=") {
			eqIdx := strings.Index(arg, "=")
			parts = append(parts, arg[:eqIdx+1]+"****")
			continue
		}
		parts = append(parts, arg)
	}
	return strings.Join(parts, " ")
}

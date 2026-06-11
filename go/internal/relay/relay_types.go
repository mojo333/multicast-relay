package relay

import (
	"bytes"
	"net"
	"net/netip"
	"time"

	"github.com/mojo333/multicast-relay/internal/cipher"
	"github.com/mojo333/multicast-relay/internal/logger"

	"golang.org/x/sys/unix"
)

// remoteReadBuf holds per-connection read state for remote TCP relay connections.
type remoteReadBuf struct {
	buf        bytes.Buffer
	msgLen     int
	lastActive time.Time
}

// ssdpSearchSource tracks the most recent SSDP search source for unicast reply routing.
type ssdpSearchSource struct {
	addr netip.Addr
	port uint16
	set  bool
}

// parsedFilter is a pre-parsed ifFilter entry.
type parsedFilter struct {
	prefix netip.Prefix
	ifaces []string
}

// RelayAddr stores a multicast/broadcast address and port pair.
type RelayAddr struct {
	Addr netip.Addr
	Port int
}

// Transmitter holds the per-interface transmitter socket and metadata.
type Transmitter struct {
	Relay     RelayAddr
	Interface string
	Addr      netip.Addr // interface IP address
	MAC       net.HardwareAddr
	Network   netip.Prefix // interface network prefix, replaces Netmask string
	Broadcast netip.Addr   // interface broadcast address
	Socket    int          // raw AF_PACKET socket fd
	Service   string
}

// Receiver wraps a raw receive socket fd.
type Receiver struct {
	fd int
}

// connectResult carries the outcome of an async remote dial attempt.
type connectResult struct {
	ra   *RemoteAddr
	conn net.Conn
	err  error
}

// RemoteAddr holds state for a remote relay connection target.
type RemoteAddr struct {
	Addr           string
	Conn           net.Conn
	Connecting     bool
	ConnectFailure time.Time
}

// Config holds all configuration for the PacketRelay.
type Config struct {
	Interfaces           []string
	NoTransmitInterfaces []string
	IfFilter             string
	WaitForIP            bool
	TTL                  int
	OneInterface         bool
	AllowNonEther        bool
	SSDPUnicastAddr      string
	MDNSForceUnicast     bool
	Masquerade           []string
	Listen               []string
	Remote               []string
	RemotePort           int
	RemoteRetry          int
	NoRemoteRelay        bool
	AESKey               string
	Logger               *logger.Logger
}

// PacketRelay is the main relay engine.
type PacketRelay struct {
	interfaces           []string
	noTransmitInterfaces map[string]bool
	parsedFilters        []parsedFilter
	ssdpUnicastAddr      netip.Addr // zero value means disabled
	mdnsForceUnicast     bool
	wait                 bool
	ttl                  int
	oneInterface         bool
	allowNonEther        bool
	masquerade           map[string]bool

	logger *logger.Logger

	transmitters []Transmitter
	receivers    []Receiver
	etherAddrs   map[netip.Addr]net.HardwareAddr // multicast/broadcast IP → MAC

	// ssdpSrc tracks the most recent SSDP M-SEARCH source for unicast reply routing.
	// Only accessed from the single-threaded main loop.
	ssdpSrc ssdpSearchSource

	// Ring buffer for duplicate detection.
	// Only accessed from the single-threaded main loop (Loop -> processPacket).
	recentChecksums [maxRecentChecksums]uint16
	checksumIdx     int
	checksumCount   int

	listenAddr        []string
	listener          *net.TCPListener
	acceptCh          chan net.Conn
	connectResultCh   chan connectResult // receives async dial outcomes
	remoteAddrs       []*RemoteAddr
	remotePort        int
	remoteRetry       int
	noRemoteRelay     bool
	aes               *cipher.Cipher
	remoteConnections []net.Conn
	connectedRemotes  []net.Conn // cached union of all active remote connections
	connsDirty        bool       // true when connectedRemotes needs rebuilding
	remoteReadBufs    map[net.Conn]*remoteReadBuf

	// remoteTmpBuf is a pre-allocated read buffer for remote TCP connection reads.
	remoteTmpBuf []byte

	// Pre-allocated poll structures rebuilt when receivers change.
	pollFds   []unix.PollFd
	pollDirty bool

	// done signals Loop() to exit cleanly.
	done chan struct{}
}

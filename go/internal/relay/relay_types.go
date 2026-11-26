package relay

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/mojo333/multicast-relay/internal/cipher"
	"github.com/mojo333/multicast-relay/internal/logger"

	"golang.org/x/sys/unix"
)

// remotePacket is a decoded packet delivered from a connection's reader
// goroutine to the main loop for relaying.
type remotePacket struct {
	senderAddr netip.Addr
	data       []byte
	from       net.Conn // the connection it arrived on, which must not get it back
}

// sessionConn is an authenticated remote connection together with the keys that
// are valid for it alone, one per direction.
type sessionConn struct {
	net.Conn
	send, recv *cipher.Cipher
}

// remoteWriter owns the writer goroutine for a single remote connection.
// The event loop enqueues plaintext frames on ch; the goroutine encrypts and
// writes them so a slow peer cannot block the loop. done is closed to stop the
// goroutine.
type remoteWriter struct {
	conn net.Conn
	ch   chan []byte
	done chan struct{}
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
	// sendFailing keeps a dead interface from logging every packet.
	sendFailing bool
}

// Receiver wraps a raw receive socket fd.
type Receiver struct {
	fd    int
	port  int    // raw sockets see every UDP port, so the loop filters on this one
	iface string // set when the socket is bound to one interface
	// readdressAs replaces a limited broadcast destination with the arrival
	// interface's broadcast address, so that one code path relays both.
	readdressAs netip.Addr
}

// relayRule is one relayed address and port.
type relayRule struct {
	addr    netip.Addr
	port    int
	service string
}

// listedInterface is an interface named in --interfaces, whether or not packets
// are transmitted on it, as it looked when its sockets were opened.
type listedInterface struct {
	spec    string
	info    InterfaceResult
	missing bool // already reported as unusable
}

// seenPacket is one entry of the duplicate filter.
type seenPacket struct {
	key uint64
	at  time.Time
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

	relays       []relayRule
	listed       []listedInterface
	matchedNames map[string]string // interface spec to the name it last matched
	transmitters []Transmitter
	receivers    []Receiver
	reopenFailed bool                            // a failed reopening has been reported
	etherAddrs   map[netip.Addr]net.HardwareAddr // multicast/broadcast IP → MAC

	// ssdpSrc tracks the most recent SSDP M-SEARCH source for unicast reply routing.
	// Only accessed from the single-threaded main loop.
	ssdpSrc ssdpSearchSource

	// Ring buffer for duplicate detection.
	// Only accessed from the single-threaded main loop (Loop -> processPacket).
	recent    [maxRecentPackets]seenPacket
	recentIdx int

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
	connectedRemotes  []net.Conn                 // cached union of all active remote connections
	connsDirty        bool                       // true when connectedRemotes needs rebuilding
	remoteWriters     map[net.Conn]*remoteWriter // per-connection writer goroutines
	remoteSeq         uint64                     // monotonic sequence for outbound frames

	// remotePacketCh receives decoded packets from per-connection reader
	// goroutines; remoteFailedCh receives connections whose reader hit an error.
	remotePacketCh chan remotePacket
	remoteFailedCh chan net.Conn

	// ARP resolution cache for SSDP unicast reply routing (main-loop only).
	arpCacheIP   string
	arpCacheMAC  net.HardwareAddr
	arpCacheTime time.Time

	// Pre-allocated poll structures rebuilt when receivers change.
	pollFds   []unix.PollFd
	pollDirty bool

	// done signals Loop() to exit cleanly.
	done      chan struct{}
	closeOnce sync.Once
}

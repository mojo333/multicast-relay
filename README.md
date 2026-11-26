Relay broadcast and multicast packets between interfaces
--------------------------------------------------------

This is a port to Go of Al Smith's brilliant multicast-relay
implementation originally written in Python. Additional fixes and
optimisations have been made.

To run this on an Unifi Dream Machine Pro use the command

`nohup /data/multicast-relay/multicast-relay-arm64 --interfaces br0 br50 br99 </dev/null >/dev/null 2>&1 &`

Ensure that the path points to the binary and that the interfaces
are the ones you want to listen to.

Useful, for example, if you have Sonos speakers on one interface, or VLAN,
and you want to be able to control them from devices on a different
interface/VLAN. Similar for Chromecast devices.

By default, SSDP multicast packets received on 239.255.255.250:1900 are
relayed to the other interfaces listed, as well as multicast DNS packets
received on 224.0.0.251:5353.

Broadcast UDP packets received on port 6969 are also relayed by default:
this is used by Sonos during the initial device-discovery phase, initiated
by pressing either the infinity button or the play+volume up buttons,
depending on your Sonos speaker.

Please note that even when your devices have discovered one another, at
least in the Sonos case, a unicast connection will be established from
the speakers back to the controlling-telephone. You will need to make sure
that IP forwarding is enabled (`echo 1 > /proc/sys/net/ipv4/ip_forward`) and
that no firewalling is in place that would prevent connections being
established.

`usage: multicast-relay-<platform> --interfaces INTERFACE [INTERFACE ...] [--noTransmitInterfaces INTERFACE ...] [--ifFilter IFFILTER] [--ssdpUnicastAddr ADDR] [--relay BROADCAST_OR_MULTICAST:PORT ...] [--noMDNS] [--mdnsForceUnicast] [--noSSDP] [--noSonosDiscovery] [--oneInterface] [--allowNonEther] [--masquerade INTERFACE ...] [--wait] [--ttl TTL] [--listen REMOTE_ADDRESS ...] [--remote REMOTE_ADDRESS ...] [--remotePort PORT] [--remoteRetry SECS] [--noRemoteRelay] [--aes KEY] [--drop-user USER] [--foreground] [--logfile FILE] [--verbose] [--monitor FILE]`

Options that take several values accept them after one flag
(`--interfaces br0 br50`) or as repeated flags.

`--interfaces` specifies the >= 2 interfaces that you desire to listen to and
relay between. You can specify an interface by name, by IP address, or by
network/netmask combination (e.g. 10.0.0.0/24 in the last case). With certain
flags below, the minimum number of interfaces drops to >= 1.

`--noTransmitInterfaces` specifies interface(s) that are listen-only.

`--ifFilter` specifies a JSON file where one can state that a source address
A.B.C.D/M is only to be relayed to specific interfaces. This can be useful
in applications such as a hotel where relaying for one guest room may only
discover device(s) that are in the same guest room. For example:

```json
{
  "10.0.0.0/16": ["br0", "br50"],
  "10.0.1.5": ["br0"]
}
```

Where several rules match a source, the most specific one applies. A source that
matches no rule is relayed everywhere. Use interface names, not addresses. The
filter covers local interfaces only: it does not limit what is sent to remote
relays.

`--ssdpUnicastAddr` specifies an IP address to listen on for SSDP unicast replies.

`--relay` specifies additional broadcast or multicast addresses to relay. Use
`255.255.255.255:PORT` for broadcasts, which covers both that address and each
interface's own broadcast address.

`--noMDNS` disables mDNS relaying.

`--mdnsForceUnicast` forces relayed mDNS packets to have the UNICAST-RESPONSE bit set.

`--noSSDP` disables SSDP relaying.

`--noSonosDiscovery` disables broadcast udp/6969 relaying.

`--oneInterface` support for one interface connected to two networks. Use with
caution - watch out for packet storms (although the IP checksum list ought
to still prevent such a thing from happening).

`--allowNonEther` supports non-ethernet interfaces to be relayed [experimental].

`--masquerade` rewrites the source address of outbound packets on the given
interface(s) to that interface's own address, similar to NAT masquerading.

`--wait` indicates that the relay should wait for an IPv4 address to be assigned
to each interface rather than bailing immediately if an interface is yet to be
assigned an address.

If a listed interface is later recreated or given a new address, the relay
notices within a few seconds and reopens its sockets once every listed interface
is available. With `--drop-user` it no longer has permission to do that, so it
exits with an error: run it under a service manager that restarts it.

`--ttl` sets the TTL on outbound packets (1-255); default leaves the TTL unchanged.

`--listen` for connections from the specified remote host(s), given as IPv4
addresses.

`--remote` connect to the specified remote host. If either --listen or --remote
are specified, then one can also specify just one local interface with --interfaces.

`--remotePort` use the specified port for remote communications (default: 1900).

`--remoteRetry` if the remote connection fails, wait at least this number of seconds before retrying (default: 5).

`--noRemoteRelay` do not pass packets received from one remote relay on to
others. Local packets are still sent to remote relays.

`--aes` use the specified string to encrypt/decrypt data packets sent to remote
relays. Can also be set via the `MULTICAST_RELAY_AES_KEY` environment variable.

**Upgrading from v2.8 or earlier:** the remote protocol has changed, with or
without `--aes`, so every `--listen` and `--remote` peer must be upgraded at the
same time. Mixed versions do not relay to each other.

`--drop-user` drop root privileges to this unprivileged user after socket setup
(Linux only, requires starting as root).

`--foreground` also logs to stdout as well as to the syslog. The relay never
moves itself to the background, so use `nohup` or a service manager for that.

`--logfile` saves log data to the specified file.

`--verbose` steps up the logging.

`--monitor` writes startup, error, and shutdown events to the specified log file.


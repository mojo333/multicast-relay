Relay broadcast and multicast packets between interfaces
--------------------------------------------------------

This is a port to Go of Al Smith's brilliant multicast-relay
implementation originally written in Python. Additional fixes and
optimisations have been made.

Useful, for example, if you have Sonos speakers on one interface, or VLAN,
and you want to be able to control them from devices on a different
interface/VLAN. Similar for Chromecast devices.

See [Running on a UniFi Dream Machine Pro](#running-on-a-unifi-dream-machine-pro)
for installation on that device.

By default, SSDP multicast packets received on 239.255.255.250:1900 are
relayed to the other interfaces listed, as well as multicast DNS packets
received on 224.0.0.251:5353.

Broadcast UDP packets received on port 6969 are also relayed by default:
this is used by Sonos during the initial device-discovery phase, initiated
by pressing either the infinity button or the play+volume up buttons,
depending on your Sonos speaker.

Packets that the relay's own host sends from a listed interface's address are
not copied to the other local interfaces. Services on the host, such as a
router's own discovery, choose which networks to send on, so copying their
packets would put them on networks they did not choose. A service that sends on
only one network is therefore not heard on the others. These packets are still
sent to remote relays. Only one address per interface is recognised, so packets
sent from a secondary address are copied as usual.

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
relay between. You can specify an interface by name, by IP address or by
network/netmask combination (e.g. 10.0.0.0/24 in the last case). With certain
flags below, the minimum number of interfaces drops to >= 1. Traffic from
interfaces that are not listed is not relayed.

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

Where several rules match a source, the most specific one applies, and two rules
for the same range stop the relay at start-up. A source that matches no rule is
relayed everywhere. Use interface names, not addresses. The filter covers local
interfaces only: it does not limit what is sent to remote relays.

`--ssdpUnicastAddr` specifies one of this host's IP addresses to listen on for
SSDP unicast replies. Relayed searches carry this address and port 1901 as their
source, and replies are passed back to the most recent searcher. Replies are only
accepted from listed networks, except with `--oneInterface`.

`--relay` specifies additional broadcast or multicast addresses to relay. Use
`255.255.255.255:PORT` for broadcasts, which covers both that address and each
interface's own broadcast address.

`--noMDNS` disables mDNS relaying.

`--mdnsForceUnicast` forces relayed mDNS queries to have the UNICAST-RESPONSE bit set.

`--noSSDP` disables SSDP relaying.

`--noSonosDiscovery` disables broadcast udp/6969 relaying.

`--oneInterface` supports one interface connected to two networks. Packets from
senders outside the interface's own subnet are relayed back out of it. Use with
caution and watch out for packet storms, although the duplicate filter, which
ignores a repeat of a packet seen in the last 2 seconds, ought to prevent them.

`--allowNonEther` supports non-ethernet interfaces to be relayed [experimental].

`--masquerade` rewrites the source address of outbound packets on the given
interface(s) to that interface's own address, similar to NAT masquerading.

`--wait` indicates that the relay should wait for an IPv4 address to be assigned
to each interface rather than bailing immediately if an interface is yet to be
assigned an address.

If a listed interface is later recreated or given a new address, the relay
notices within a few seconds and reopens its sockets once every listed interface
is available. An interface listed by address or CIDR block is followed by its
name if that no longer matches. With `--drop-user` the relay no longer has
permission to reopen sockets, so it exits with an error: run it under a service
manager that restarts it.

`--ttl` sets the TTL on outbound packets (1-255); default leaves the TTL unchanged.

`--listen` accepts connections on `--remotePort` from the specified remote
relay(s), given as IPv4 addresses.

`--remote` connects to the specified remote relay(s). A relay uses either
`--listen` or `--remote`, not both, and with either of them one local interface in
`--interfaces` is enough.

`--remotePort` sets the port for remote communications (default: 1900).

`--remoteRetry` sets the minimum number of seconds to wait before retrying a
failed remote connection (default: 5).

`--noRemoteRelay` stops packets received from one remote relay being passed on to
others. Local packets are still sent to remote relays.

`--aes` uses the specified string to authenticate remote relays to each other and
to encrypt the packets sent between them. Without it the traffic is unencrypted
and a listening relay trusts any connection from a `--listen` address. The key can
also be set in the `MULTICAST_RELAY_AES_KEY` environment variable, which keeps it
out of the process list.

`--drop-user` drops root privileges to this unprivileged user after socket setup
(Linux only, requires starting as root).

`--foreground` logs to stdout as well as to the syslog. The relay never moves
itself to the background, so use `nohup` or a service manager for that.

`--logfile` saves log data to the specified file.

`--verbose` also logs informational messages, including a line for every relayed
packet. Without it only warnings and errors are logged.

`--monitor` writes startup, shutdown, warning and error events to the specified
log file.

Running on a UniFi Dream Machine Pro
------------------------------------

Run the relay as a systemd service, so that it is restarted if it crashes or
is killed. These steps assume the binary is in `/data/multicast-relay/` and that
your UDM runs the executable scripts in `/data/on_boot.d/` at start-up, which
needs a boot script runner such as `udm-boot`.

1. Create `/data/multicast-relay/multicast-relay.service`, replacing the
   interfaces with the ones you want to relay between:

   ```ini
   [Unit]
   Description=multicast-relay
   Wants=network-online.target
   After=network-online.target
   # Never give up restarting, for example while interfaces are still coming up at boot.
   StartLimitIntervalSec=0

   [Service]
   ExecStart=/data/multicast-relay/multicast-relay-arm64 --monitor /data/multicast-relay/multicast-relay-monitor.log --interfaces br50 br99
   Restart=always
   RestartSec=5
   ```

2. Create `/data/on_boot.d/10-multicast-relay.sh`:

   ```sh
   #!/bin/sh
   # Reinstalls the unit on every boot in case a firmware update has cleared /etc.
   cp /data/multicast-relay/multicast-relay.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl restart multicast-relay
   ```

3. Stop any relay that is already running, for example one started with `nohup`,
   because two relays send every packet twice. Then make the script executable
   and run it:

   ```sh
   chmod +x /data/on_boot.d/10-multicast-relay.sh
   /data/on_boot.d/10-multicast-relay.sh
   ```

Check it with `systemctl status multicast-relay`. The unit is deliberately not
enabled, because the boot script installs and starts it. After editing the unit
file or replacing the binary, run the boot script again. A mistake in the options
makes the service restart every 5 seconds, so check the status after any change.

Upgrading from v2.8 or earlier
------------------------------

- The remote protocol has changed, with or without `--aes`, so every `--listen`
  and `--remote` peer must be upgraded at the same time. Mixed versions do not
  relay to each other.
- Traffic from interfaces that are not listed is no longer relayed.
- A value after a list option now belongs to that option, where v2.8 added loose
  values to `--interfaces`.
- A loose value after any other option, a `--listen` host name and two
  `--ifFilter` rules for one range now stop the relay at start-up.
- Only traffic matching a relay rule is sent to remote relays.
- SSDP unicast replies are accepted only from listed networks and sent only to the
  searcher's network.
- With `--drop-user`, a recreated or readdressed interface makes the relay exit.
- Packets sent by the relay's own host are no longer copied between local
  interfaces.


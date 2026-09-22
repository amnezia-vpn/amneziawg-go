// Package uidfilter is the mechanism half of the "Strict Split Tunneling"
// feature (issue amnezia-client#2457) for the AmneziaWG datapath. It gates
// OUTBOUND packets read from the Android tun device: packets whose owning app
// is disallowed by the split-tunnel policy are dropped before encryption, so an
// app that bypasses the OS split-tunnel rules (via SO_BINDTODEVICE on tun0)
// cannot leak traffic — and the VPN server IP — into the tunnel.
//
// The policy (resolving the owning app UID and applying include/exclude rules)
// lives outside this package and is injected via Set as a PacketFilter — on
// Android it bridges through JNI to ConnectivityManager.getConnectionOwnerUid.
// Because this datapath is packet-based (the filter would otherwise be consulted
// for every packet), a TCP flow is judged only on packets that open a connection
// (SYN set), and decisions are cached per flow (proto+srcIP+srcPort) so the
// expensive cross-language call happens at most once per new flow.
//
// While a filter is installed, packets whose owner cannot be resolved are
// dropped: anything but TCP and UDP, IP fragments, and IPv6 packets with
// extension headers. An unprivileged app can send ICMP echo through a ping
// socket bound to the tun device, and the platform resolves owners for TCP and
// UDP only, so passing such packets would reopen the bypass.
//
// When no filter is installed (the default), AllowOutboundPacket returns true
// after a single atomic load, and Supported is false off Android, so callers can
// drop the branch at compile time and the legacy path costs nothing.
package uidfilter

import (
	"net"
	"sync/atomic"
	"time"
)

// PacketFilter decides whether a new outbound flow may enter the tunnel.
// network is "tcp" or "udp"; src is the originating app endpoint (the tun-side
// source), dst is the destination. Implementations resolve the owning app UID
// and apply the split-tunnel policy; they must be safe for concurrent use.
type PacketFilter interface {
	Allow(network, srcIP string, srcPort int, dstIP string, dstPort int) bool
}

type holder struct{ f PacketFilter }

var current atomic.Pointer[holder]

// Set installs f as the active filter, or removes it when f is nil (restoring
// legacy allow-all). It also drops the decision cache. Safe to call from any
// goroutine.
func Set(f PacketFilter) {
	cache.Store(newDecisionCache())
	if f == nil {
		current.Store(nil)
		return
	}
	current.Store(&holder{f: f})
}

// Get returns the active filter, or nil when none is installed.
func Get() PacketFilter {
	if h := current.Load(); h != nil {
		return h.f
	}
	return nil
}

// AllowOutboundPacket parses the 5-tuple from an outbound IP packet and returns
// whether it may be sent. It returns true when no filter is installed, and false
// for a packet whose owner cannot be resolved (see the package comment). TCP
// packets without SYN are passed through: a connection whose SYN was denied never
// becomes established, so any later packet belongs to an allowed one. Judging
// those again would misread closing sockets, which the kernel re-attributes to
// UID 0 once the app has closed them. Other packets are cached per flow, so the
// filter is consulted at most once per (proto, source address, source port).
//
// It is written for the single goroutine that reads the tun device, and the
// decision cache assumes that; Set may be called from anywhere.
func AllowOutboundPacket(packet []byte) bool {
	f := Get()
	if f == nil {
		return true
	}

	proto, src, srcPort, dst, dstPort, ok := parse5Tuple(packet)
	if !ok {
		return false
	}
	if proto == ipProtoTCP {
		if flags, ok := tcpFlags(packet); ok && flags&tcpFlagSYN == 0 {
			return true
		}
	}

	key := flowKey{proto: proto, srcPort: uint16(srcPort)}
	copy(key.srcIP[:], src.To16())

	c := cache.Load()
	if allow, found := c.get(key); found {
		return allow
	}

	allow := f.Allow(networkName(proto), src.String(), srcPort, dst.String(), dstPort)
	c.put(key, allow)
	return allow
}

const (
	ipProtoTCP = 6
	ipProtoUDP = 17

	tcpOffsetFlags = 13
	tcpFlagSYN     = 0x02

	ipv4FlagMF         = 0x2000
	ipv4MaskFragOffset = 0x1fff

	// IP-header field offsets (bytes from the start of the IP packet).
	ipv4OffsetSrc = 12
	ipv4OffsetDst = 16
	ipv6OffsetSrc = 8
	ipv6OffsetDst = 24
)

func networkName(proto uint8) string {
	if proto == ipProtoTCP {
		return "tcp"
	}
	return "udp"
}

// parse5Tuple extracts (proto, srcIP, srcPort, dstIP, dstPort) from an outbound
// IPv4/IPv6 packet. ok is false for non-TCP/UDP, fragmented or malformed
// packets, and for IPv6 with extension headers before the L4 header.
func parse5Tuple(p []byte) (proto uint8, srcIP net.IP, srcPort int, dstIP net.IP, dstPort int, ok bool) {
	if len(p) < 1 {
		return
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return
		}
		ihl := int(p[0]&0x0f) * 4
		if ihl < 20 || len(p) < ihl+4 {
			return
		}
		if frag := int(p[6])<<8 | int(p[7]); frag&(ipv4FlagMF|ipv4MaskFragOffset) != 0 {
			return // a fragment: only the first one carries ports
		}
		if !isTCPOrUDP(p[9]) {
			return
		}
		srcIP = net.IP(p[ipv4OffsetSrc : ipv4OffsetSrc+net.IPv4len])
		dstIP = net.IP(p[ipv4OffsetDst : ipv4OffsetDst+net.IPv4len])
		srcPort = int(p[ihl])<<8 | int(p[ihl+1])
		dstPort = int(p[ihl+2])<<8 | int(p[ihl+3])
		return p[9], srcIP, srcPort, dstIP, dstPort, true
	case 6:
		if len(p) < 40+4 {
			return
		}
		if !isTCPOrUDP(p[6]) { // next-header; extension headers not walked
			return
		}
		srcIP = net.IP(p[ipv6OffsetSrc : ipv6OffsetSrc+net.IPv6len])
		dstIP = net.IP(p[ipv6OffsetDst : ipv6OffsetDst+net.IPv6len])
		srcPort = int(p[40])<<8 | int(p[41])
		dstPort = int(p[42])<<8 | int(p[43])
		return p[6], srcIP, srcPort, dstIP, dstPort, true
	}
	return
}

func isTCPOrUDP(proto byte) bool {
	return proto == ipProtoTCP || proto == ipProtoUDP
}

// tcpFlags returns the flags byte of a TCP packet already accepted by
// parse5Tuple. ok is false when the header is too short to hold it.
func tcpFlags(p []byte) (flags byte, ok bool) {
	l4 := 40
	if p[0]>>4 == 4 {
		l4 = int(p[0]&0x0f) * 4
	}
	if len(p) < l4+tcpOffsetFlags+1 {
		return 0, false
	}
	return p[l4+tcpOffsetFlags], true
}

// --- per-flow decision cache ---

const (
	cacheTTL        = 10 * time.Second
	cacheMaxEntries = 4096

	// The clock is read once per this many lookups instead of on every packet:
	// time.Now() costs more than the lookup it guards. Between reads an entry can
	// outlive its TTL by the time those lookups take, which is microseconds under
	// the load where it matters. A miss reads the clock anyway.
	clockEvery = 64
)

type flowKey struct {
	srcIP   [16]byte
	srcPort uint16
	proto   uint8
}

type cacheEntry struct {
	expiresAt int64 // unix nanos
	allow     bool
}

// decisionCache belongs to the goroutine that reads the tun device: it is not
// guarded, and Set swaps in a fresh one rather than mutating this.
type decisionCache struct {
	m       map[flowKey]cacheEntry
	now     int64 // the clock as last read
	lookups uint32
}

var cache atomic.Pointer[decisionCache]

func init() { cache.Store(newDecisionCache()) }

func newDecisionCache() *decisionCache {
	return &decisionCache{m: make(map[flowKey]cacheEntry), now: time.Now().UnixNano()}
}

func (c *decisionCache) tick() int64 {
	c.lookups++
	if c.lookups%clockEvery == 0 {
		c.now = time.Now().UnixNano()
	}
	return c.now
}

func (c *decisionCache) get(k flowKey) (allow, found bool) {
	e, ok := c.m[k]
	if !ok {
		return false, false
	}
	if e.expiresAt > c.tick() {
		return e.allow, true
	}
	// Possibly stale only because the clock is, so read it before dropping.
	c.now = time.Now().UnixNano()
	if e.expiresAt > c.now {
		return e.allow, true
	}
	delete(c.m, k)
	return false, false
}

func (c *decisionCache) put(k flowKey, allow bool) {
	now := time.Now().UnixNano()
	c.now = now
	if len(c.m) >= cacheMaxEntries {
		for kk, ee := range c.m {
			if ee.expiresAt <= now {
				delete(c.m, kk)
			}
		}
		if len(c.m) >= cacheMaxEntries {
			c.m = make(map[flowKey]cacheEntry)
		}
	}
	c.m[k] = cacheEntry{allow: allow, expiresAt: now + cacheTTL.Nanoseconds()}
}

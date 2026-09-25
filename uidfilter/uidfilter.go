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
// for every packet), a TCP connection is judged on its SYN alone, every SYN
// afresh, and a UDP flow's verdict is cached per 5-tuple for a few seconds, so
// the expensive cross-language call happens about once per new flow.
//
// That call is slow — a binder call with a netlink socket-table walk behind it
// — so it never runs on the goroutine that reads the tun device. A packet of a
// flow not yet judged is copied and held, within limits on packets, bytes and
// time, while a small pool of workers asks the filter; the verdict then sends
// or drops what was held. No packet of a flow leaves before its verdict, and
// flows already judged do not wait for the ones being judged. While too many
// flows wait, packets of new ones are dropped rather than held.
//
// The platform can only name the owner of a socket that still exists. A
// datagram sent from a socket closed right after sending may be judged too
// late, and is then dropped like one of an unknown owner.
//
// While a filter is installed, packets whose owner cannot be resolved are
// dropped: anything but TCP and UDP, IP fragments, and IPv6 packets with
// extension headers. An unprivileged app can send ICMP echo through a ping
// socket bound to the tun device, and the platform resolves owners for TCP and
// UDP only, so passing such packets would reopen the bypass.
//
// When no filter is installed (the default), Gate.AllowOutboundPacket returns
// true after a single atomic load, and Supported is false off Android, so
// callers can drop the branch at compile time and the legacy path costs nothing.
package uidfilter

import (
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// PacketFilter decides whether a new outbound flow may enter the tunnel.
// network is "tcp" or "udp"; src is the originating app endpoint (the tun-side
// source), dst is the destination. Implementations resolve the owning app UID
// and apply the split-tunnel policy; they are called from several goroutines at
// once and must be safe for concurrent use.
type PacketFilter interface {
	Allow(network, srcIP string, srcPort int, dstIP string, dstPort int) bool
}

// Releaser sends a packet that was held while its flow was being judged. It is
// called from a worker goroutine, never from the one that reads the tun device.
type Releaser interface {
	ReleaseOutboundPacket(packet []byte)
}

// holder is one installed filter with the workers that call it. Set replaces
// it as a whole, and a Gate starts afresh when it sees a new one, so nothing
// decided under one filter is used under the next.
type holder struct {
	f     PacketFilter
	start time.Time    // when the filter was installed
	now   atomic.Int64 // a coarse monotonic clock: nanoseconds since start

	jobs chan job
	done chan struct{} // closed when Set replaces this holder

	// release is held for reading while a verdict's packets are sent, and for
	// writing while the holder is retired, so no packet leaves on a verdict of
	// a filter that Set has already replaced.
	release sync.RWMutex
}

type job struct {
	s   *flowState
	key flowKey
}

var current atomic.Pointer[holder]

// Set installs f as the active filter, or removes it when f is nil (restoring
// legacy allow-all). The new filter starts with empty caches and nothing
// pending. Packets still held for the old one are dropped: once Set returns, no
// packet leaves on the old filter's verdict. Safe to call from any goroutine.
func Set(f PacketFilter) {
	var h *holder
	if f != nil {
		h = newHolder(f)
	}
	if old := current.Swap(h); old != nil {
		old.release.Lock()
		close(old.done)
		old.release.Unlock()
	}
}

// Get returns the active filter, or nil when none is installed.
func Get() PacketFilter {
	if h := current.Load(); h != nil {
		return h.f
	}
	return nil
}

// Gate is the filter state of one tun reader: its verdict cache and its flows
// waiting for a verdict. The zero value is ready to use. It belongs to the
// goroutine that reads the tun device, so each device has its own.
type Gate struct {
	h *holder    // the filter s was made for
	s *flowState // nil until a filter is first seen
}

// AllowOutboundPacket parses the 5-tuple from an outbound IP packet and returns
// whether it may be sent now. It returns true when no filter is installed.
// False means the packet must not be sent now: its owner cannot be resolved
// (see the package comment), its flow is denied, or its flow is not judged yet
// — then the packet is copied and handed to r if the flow is allowed. Either
// way the caller may reuse the buffer.
//
// TCP packets without SYN are passed through: a connection whose SYN was denied
// never becomes established, so any later packet belongs to an allowed one.
// Judging those again would misread closing sockets, which the kernel
// re-attributes to UID 0 once the app has closed them. Every SYN is judged,
// even on a 5-tuple judged before, since a new socket may have taken it over.
// UDP verdicts are cached per 5-tuple for cacheTTL.
func (g *Gate) AllowOutboundPacket(packet []byte, r Releaser) bool {
	h := current.Load()
	if h == nil {
		return true
	}
	if g.h != h {
		g.h, g.s = h, newFlowState()
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

	key := flowKey{proto: proto, ipLen: uint8(len(src)), srcPort: uint16(srcPort), dstPort: uint16(dstPort)}
	copy(key.srcIP[:], src)
	copy(key.dstIP[:], dst)

	now := h.now.Load()
	if proto == ipProtoUDP {
		if allow, found := g.s.cache.get(key, now); found {
			return allow
		}
	}
	return g.s.hold(h, key, packet, r, now)
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

// --- flows waiting for a verdict ---

const (
	// workers is how many filter calls may run at once. Each runs on its own
	// locked OS thread, so a filter that attaches the thread to a runtime (JNI
	// does) attaches this many threads and no more.
	workers = 4

	// maxPendingFlows bounds the flows of one Gate waiting for a verdict. Past
	// it, packets of new flows are dropped, not held: the filter is falling
	// behind, and holding more would only grow memory. Flows already judged are
	// unaffected.
	maxPendingFlows = 256

	// maxHeldPerFlow is how many packets of one flow are held until its verdict:
	// enough for a SYN and its retransmit, or a DNS query and its retry.
	maxHeldPerFlow = 4

	// maxHeldBytes bounds the memory held by one Gate.
	maxHeldBytes = 1 << 20

	// maxHoldTime is how old a held packet may be when its verdict arrives and
	// still be sent. An older one is dropped: the sender has retried or given
	// up by then. It is measured on the coarse clock, so up to clockInterval
	// longer.
	maxHoldTime = 2 * time.Second

	// clockInterval is how often the coarse clock advances. The cache and the
	// hold limit read it instead of time.Now(), which costs more than a cache
	// lookup; it is advanced by a timer rather than by lookups so that it stays
	// right across an idle tunnel.
	clockInterval = time.Second
)

// flowState is what one Gate keeps for one filter. The cache belongs to the
// tun-read goroutine; the rest is shared with the workers, under mu.
type flowState struct {
	cache decisionCache

	mu        sync.Mutex
	pending   map[flowKey]*pendingFlow
	waiting   int       // pending flows without a verdict yet
	heldBytes int       // bytes of the packets held
	decided   []flowKey // pending flows with a verdict, not yet collected
}

type pendingFlow struct {
	held    []heldPacket // in the order they were read
	r       Releaser
	decided bool
	allow   bool
}

type heldPacket struct {
	data []byte // a copy: the reader reuses its buffers
	at   int64  // the coarse clock when it was read
}

func newHolder(f PacketFilter) *holder {
	h := &holder{
		f:     f,
		start: time.Now(),
		jobs:  make(chan job, maxPendingFlows),
		done:  make(chan struct{}),
	}
	go h.tick()
	for i := 0; i < workers; i++ {
		go h.work()
	}
	return h
}

func newFlowState() *flowState {
	return &flowState{
		cache:   decisionCache{m: make(map[flowKey]cacheEntry)},
		pending: make(map[flowKey]*pendingFlow),
	}
}

// tick advances the coarse clock until the holder is replaced. The clock only
// moves forward.
func (h *holder) tick() {
	t := time.NewTicker(clockInterval)
	defer t.Stop()
	for {
		select {
		case <-h.done:
			return
		case now := <-t.C:
			if since := int64(now.Sub(h.start)); since > h.now.Load() {
				h.now.Store(since)
			}
		}
	}
}

// hold handles a packet whose flow has no cached verdict. It runs on the
// tun-read goroutine and returns the packet's verdict if the flow has one by
// now, and false if the packet was held or dropped.
func (s *flowState) hold(h *holder, key flowKey, packet []byte, r Releaser, now int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.collectDecided(now)

	if pf, ok := s.pending[key]; ok {
		if !pf.decided {
			if len(pf.held) < maxHeldPerFlow && s.heldBytes+len(packet) <= maxHeldBytes {
				pf.held = append(pf.held, heldPacket{append([]byte(nil), packet...), now})
				s.heldBytes += len(packet)
			}
			return false
		}
		delete(s.pending, key)
		if key.proto != ipProtoTCP {
			s.cache.put(key, pf.allow, now)
			return pf.allow
		}
		// A SYN is judged afresh: this may be a new connection on the same 5-tuple.
	}
	if s.waiting >= maxPendingFlows || s.heldBytes+len(packet) > maxHeldBytes {
		return false // not cached: the flow is judged once there is room
	}
	select {
	case h.jobs <- job{s, key}:
	default:
		return false // other Gates keep the workers busy
	}
	s.pending[key] = &pendingFlow{held: []heldPacket{{append([]byte(nil), packet...), now}}, r: r}
	s.waiting++
	s.heldBytes += len(packet)
	return false
}

// collectDecided moves the verdicts the workers have reached into the cache,
// so that a flow which sent nothing after its first packet does not stay in
// pending. TCP verdicts are not cached. Called with s.mu held, on the tun-read
// goroutine.
func (s *flowState) collectDecided(now int64) {
	for _, key := range s.decided {
		if pf, ok := s.pending[key]; ok && pf.decided {
			delete(s.pending, key)
			if key.proto != ipProtoTCP {
				s.cache.put(key, pf.allow, now)
			}
		}
	}
	s.decided = s.decided[:0]
}

// work asks the filter about pending flows, one at a time, until Set replaces
// the holder.
func (h *holder) work() {
	runtime.LockOSThread() // never unlocked: the thread exits with the goroutine
	for {
		select {
		case <-h.done:
			return
		case j := <-h.jobs:
			h.judge(j.s, j.key)
		}
	}
}

// judge asks the filter about one flow, then sends or drops the packets held
// for it. Packets that arrive while earlier ones are being sent are held too
// and sent in the next round, so the flow keeps its order: the tun-read
// goroutine sees the verdict only once nothing is held.
func (h *holder) judge(s *flowState, key flowKey) {
	srcIP, dstIP := net.IP(key.srcIP[:key.ipLen]).String(), net.IP(key.dstIP[:key.ipLen]).String()
	allow := h.f.Allow(networkName(key.proto), srcIP, int(key.srcPort), dstIP, int(key.dstPort))

	for {
		s.mu.Lock()
		pf := s.pending[key]
		held := pf.held
		pf.held = nil
		for _, p := range held {
			s.heldBytes -= len(p.data)
		}
		if len(held) == 0 {
			pf.decided, pf.allow = true, allow
			s.waiting--
			s.decided = append(s.decided, key)
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()

		if allow && !h.send(pf.r, held) {
			return
		}
	}
}

// send hands held packets to r, dropping those held too long. It returns false,
// sending nothing, if the holder has been replaced.
func (h *holder) send(r Releaser, held []heldPacket) bool {
	h.release.RLock()
	defer h.release.RUnlock()
	select {
	case <-h.done:
		return false
	default:
	}
	now := h.now.Load()
	for _, p := range held {
		if now-p.at <= maxHoldTime.Nanoseconds() {
			r.ReleaseOutboundPacket(p.data)
		}
	}
	return true
}

// --- per-flow decision cache ---

const (
	cacheTTL        = 10 * time.Second
	cacheMaxEntries = 4096
)

// flowKey is the full 5-tuple. A key without the destination would outlive the
// socket it was made for: a later socket on the same source port, possibly of
// another app, would inherit its verdict.
type flowKey struct {
	srcIP   [16]byte
	dstIP   [16]byte
	srcPort uint16
	dstPort uint16
	proto   uint8
	ipLen   uint8 // 4 or 16: an IPv4 flow never matches an IPv6 one
}

type cacheEntry struct {
	expiresAt int64 // on the holder's coarse clock
	allow     bool
}

// decisionCache belongs to the goroutine that reads the tun device: it is not
// guarded. Times come from the holder's coarse clock.
type decisionCache struct {
	m map[flowKey]cacheEntry
}

func (c *decisionCache) get(k flowKey, now int64) (allow, found bool) {
	e, ok := c.m[k]
	if !ok {
		return false, false
	}
	if e.expiresAt > now {
		return e.allow, true
	}
	delete(c.m, k)
	return false, false
}

func (c *decisionCache) put(k flowKey, allow bool, now int64) {
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

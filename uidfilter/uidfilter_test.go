package uidfilter

import (
	"bytes"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ipv4Packet builds a minimal IPv4 packet with the given L4 protocol and ports.
func ipv4Packet(proto byte, src, dst net.IP, srcPort, dstPort int) []byte {
	p := make([]byte, 24)
	p[0] = 0x45 // version 4, IHL 5 (20 bytes)
	p[9] = proto
	copy(p[ipv4OffsetSrc:], src.To4())
	copy(p[ipv4OffsetDst:], dst.To4())
	p[20] = byte(srcPort >> 8)
	p[21] = byte(srcPort)
	p[22] = byte(dstPort >> 8)
	p[23] = byte(dstPort)
	return p
}

// tcpPacket builds a minimal IPv4 TCP packet carrying the given flags.
func tcpPacket(srcPort int, flags byte) []byte {
	p := ipv4Packet(ipProtoTCP, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), srcPort, 443)
	p = append(p, make([]byte, 16)...) // rest of the 20-byte TCP header
	p[20+tcpOffsetFlags] = flags
	return p
}

// udpPacket builds a minimal IPv4 UDP packet from 10.0.0.2 carrying one payload byte.
func udpPacket(srcPort int, dst net.IP, payload byte) []byte {
	return append(ipv4Packet(ipProtoUDP, net.IPv4(10, 0, 0, 2), dst, srcPort, 443), payload)
}

// countingFilter denies a specific source port and destination, and counts calls.
// When gate is set, every call waits until it is closed.
type countingFilter struct {
	denySrcPort int
	denyDstIP   string
	gate        chan struct{}
	calls       atomic.Int32
}

func (f *countingFilter) Allow(network, srcIP string, srcPort int, dstIP string, dstPort int) bool {
	f.calls.Add(1)
	if f.gate != nil {
		<-f.gate
	}
	return srcPort != f.denySrcPort && dstIP != f.denyDstIP
}

// recorder is a Releaser that keeps what it was given.
type recorder struct {
	mu      sync.Mutex
	packets [][]byte
}

func (r *recorder) ReleaseOutboundPacket(p []byte) {
	r.mu.Lock()
	r.packets = append(r.packets, append([]byte(nil), p...))
	r.mu.Unlock()
}

func (r *recorder) released() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.packets...)
}

// reader stands for one tun reader: a Gate and where its held packets go.
type reader struct {
	g Gate
	r recorder
}

func (rd *reader) check(p []byte) bool { return rd.g.AllowOutboundPacket(p, &rd.r) }

// install sets f and returns a reader to pass packets through.
func install(t testing.TB, f PacketFilter) *reader {
	Set(f)
	t.Cleanup(func() { Set(nil) })
	return &reader{}
}

// settle waits until the workers have judged every pending flow of rd.
func (rd *reader) settle(t testing.TB) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		rd.g.s.mu.Lock()
		waiting := rd.g.s.waiting
		rd.g.s.mu.Unlock()
		if waiting == 0 {
			return
		}
	}
	t.Fatal("pending flows were not judged in time")
}

// verdict returns what the filter decided for p's flow: the first packet is held,
// the next one after the verdict gets it directly.
func (rd *reader) verdict(t testing.TB, p []byte) bool {
	t.Helper()
	if rd.check(p) {
		return true
	}
	rd.settle(t)
	return rd.check(p)
}

// advanceClock moves the installed filter's coarse clock forward.
func advanceClock(d time.Duration) { current.Load().now.Add(int64(d)) }

func TestParse5TupleTCP(t *testing.T) {
	p := ipv4Packet(ipProtoTCP, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 54321, 443)
	proto, src, srcPort, dst, dstPort, ok := parse5Tuple(p)
	if !ok || proto != ipProtoTCP || src.String() != "10.0.0.2" || srcPort != 54321 ||
		dst.String() != "1.1.1.1" || dstPort != 443 {
		t.Fatalf("bad parse: %d %v %d %v %d ok=%v", proto, src, srcPort, dst, dstPort, ok)
	}
}

func TestParse5TupleNonTCPUDP(t *testing.T) {
	// protocol 1 = ICMP → no ports, ok must be false
	p := ipv4Packet(1, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 0, 0)
	if _, _, _, _, _, ok := parse5Tuple(p); ok {
		t.Error("expected ok=false for ICMP")
	}
}

func TestAllowNoFilter(t *testing.T) {
	Set(nil)
	var g Gate
	p := ipv4Packet(ipProtoTCP, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 4444, 443)
	if !g.AllowOutboundPacket(p, nil) {
		t.Error("expected allow when no filter installed")
	}
	if g.s != nil {
		t.Error("the gate allocated state with no filter installed")
	}
}

func TestAllowDenyAndCache(t *testing.T) {
	f := &countingFilter{denySrcPort: 4444}
	rd := install(t, f)

	denied := udpPacket(4444, net.IPv4(1, 1, 1, 1), 0)
	allowed := udpPacket(5555, net.IPv4(1, 1, 1, 1), 0)

	if rd.verdict(t, denied) {
		t.Error("expected deny for blocked source port")
	}
	if !rd.verdict(t, allowed) {
		t.Error("expected allow for unblocked source port")
	}
	if got := rd.r.released(); len(got) != 1 || !bytes.Equal(got[0], allowed) {
		t.Errorf("expected the held packet of the allowed flow alone to be released, got %d", len(got))
	}
	// Repeat: decisions must come from cache, not new filter calls.
	callsBefore := f.calls.Load()
	for i := 0; i < 5; i++ {
		if rd.check(denied) || !rd.check(allowed) {
			t.Fatal("cached verdict changed")
		}
	}
	if extra := f.calls.Load() - callsBefore; extra != 0 {
		t.Errorf("expected cache hits (no extra filter calls), got %d extra", extra)
	}
}

// A verdict belongs to the flow, not to the source port: a socket that reuses
// the port for another destination is judged afresh.
func TestFlowKeyIncludesDestination(t *testing.T) {
	f := &countingFilter{denySrcPort: -1, denyDstIP: "2.2.2.2"}
	rd := install(t, f)

	if !rd.verdict(t, udpPacket(40000, net.IPv4(1, 1, 1, 1), 0)) {
		t.Fatal("expected allow for the first destination")
	}
	if rd.verdict(t, udpPacket(40000, net.IPv4(2, 2, 2, 2), 0)) {
		t.Error("a packet from the same port to another destination passed on the old verdict")
	}
	if n := f.calls.Load(); n != 2 {
		t.Errorf("expected the filter to be asked once per destination, got %d calls", n)
	}
}

// The filter sees IPv6 addresses as they are, not as IPv4-mapped ones.
func TestIPv6FlowJudged(t *testing.T) {
	f := &countingFilter{denySrcPort: -1, denyDstIP: "2001:db8::2"}
	rd := install(t, f)
	p := make([]byte, 40+8)
	p[0] = 0x60
	p[6] = ipProtoUDP
	copy(p[ipv6OffsetSrc:], net.ParseIP("fd00::2"))
	copy(p[ipv6OffsetDst:], net.ParseIP("2001:db8::2"))
	p[40], p[41], p[42], p[43] = 0x15, 0xb3, 0x01, 0xbb
	if rd.verdict(t, p) {
		t.Error("expected deny for the IPv6 destination")
	}
}

func TestUnresolvablePacketsDroppedWhileFiltering(t *testing.T) {
	rd := install(t, &countingFilter{denySrcPort: -1})
	// ICMP echo can be sent from an unprivileged ping socket bound to tun0.
	icmp := ipv4Packet(1, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 0, 0)
	if rd.check(icmp) {
		t.Error("ICMP must be dropped while a filter is installed")
	}
	frag := ipv4Packet(ipProtoUDP, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 5555, 443)
	frag[6] = 0x20 // more fragments
	if rd.check(frag) {
		t.Error("IPv4 fragments must be dropped while a filter is installed")
	}
	rd.settle(t)
	if n := len(rd.r.released()); n != 0 {
		t.Errorf("unresolvable packets must not be held, %d were released", n)
	}
	Set(nil)
	if !rd.check(icmp) {
		t.Error("ICMP must pass when no filter is installed")
	}
}

func TestTCPJudgedOnlyOnSYN(t *testing.T) {
	f := &countingFilter{denySrcPort: 4444}
	rd := install(t, f)

	const ack, fin = 0x10, 0x11
	// Packets of an established or closing connection are not judged, even on a
	// denied port: its SYN already passed, or the connection never existed.
	for _, flags := range []byte{ack, fin} {
		if !rd.check(tcpPacket(4444, flags)) {
			t.Errorf("flags %#x: expected pass-through without SYN", flags)
		}
	}
	if n := f.calls.Load(); n != 0 {
		t.Errorf("expected no filter calls without SYN, got %d", n)
	}
	// A SYN is always held for its verdict, so what was released shows it.
	rd.check(tcpPacket(4444, tcpFlagSYN))
	rd.check(tcpPacket(5555, tcpFlagSYN))
	rd.settle(t)
	got := rd.r.released()
	if len(got) != 1 || !bytes.Equal(got[0], tcpPacket(5555, tcpFlagSYN)) {
		t.Errorf("expected only the SYN on the unblocked port to be released, got %d packets", len(got))
	}
}

// Every SYN is judged, even on a 5-tuple allowed a moment ago: a new socket may
// have taken it over.
func TestTCPEverySYNJudged(t *testing.T) {
	f := &countingFilter{denySrcPort: -1}
	rd := install(t, f)
	syn := tcpPacket(5555, tcpFlagSYN)
	for i := 1; i <= 3; i++ {
		if rd.check(syn) {
			t.Fatalf("SYN %d passed on an earlier verdict", i)
		}
		rd.settle(t)
		if n := f.calls.Load(); n != int32(i) {
			t.Fatalf("after SYN %d: expected %d filter calls, got %d", i, i, n)
		}
	}
	if n := len(rd.r.released()); n != 3 {
		t.Errorf("expected every allowed SYN to be released, got %d", n)
	}
}

// A cached verdict expires on time even when the tunnel has been idle: the
// clock does not depend on how many packets were looked up.
func TestCacheExpiresAfterIdle(t *testing.T) {
	f := &countingFilter{denySrcPort: -1}
	rd := install(t, f)
	p := udpPacket(5555, net.IPv4(1, 1, 1, 1), 0)
	if !rd.verdict(t, p) {
		t.Fatal("expected allow")
	}
	advanceClock(cacheTTL)
	for i := 0; i < 70; i++ {
		rd.check(p)
	}
	rd.settle(t)
	if n := f.calls.Load(); n != 2 {
		t.Errorf("expected the expired flow to be judged again once, got %d filter calls", n)
	}
}

// The coarse clock advances by itself, without any lookups.
func TestClockAdvancesWhileIdle(t *testing.T) {
	install(t, &countingFilter{denySrcPort: -1})
	h := current.Load()
	before := h.now.Load()
	time.Sleep(clockInterval + 200*time.Millisecond)
	if h.now.Load() <= before {
		t.Error("the clock did not advance while idle")
	}
}

// Each tun reader has its own state: a verdict reached for one is not used by another.
func TestGatesAreIndependent(t *testing.T) {
	f := &countingFilter{denySrcPort: -1}
	a := install(t, f)
	b := &reader{}
	p := udpPacket(5555, net.IPv4(1, 1, 1, 1), 0)
	if !a.verdict(t, p) || !b.verdict(t, p) {
		t.Fatal("expected allow on both readers")
	}
	if n := f.calls.Load(); n != 2 {
		t.Errorf("expected one filter call per reader, got %d", n)
	}
	if len(a.r.released()) != 1 || len(b.r.released()) != 1 {
		t.Error("each reader's held packet must go back to that reader")
	}
}

// Packets of a flow being judged wait for the verdict, a few of them, and leave
// in the order they were read.
func TestHeldPacketsReleasedInOrder(t *testing.T) {
	f := &countingFilter{denySrcPort: -1, gate: make(chan struct{})}
	rd := install(t, f)

	for i := 0; i < maxHeldPerFlow+2; i++ {
		if rd.check(udpPacket(5555, net.IPv4(1, 1, 1, 1), byte(i))) {
			t.Fatalf("packet %d passed before its flow was judged", i)
		}
	}
	if n := len(rd.r.released()); n != 0 {
		t.Fatalf("%d packets released before the verdict", n)
	}
	close(f.gate)
	rd.settle(t)

	got := rd.r.released()
	if len(got) != maxHeldPerFlow {
		t.Fatalf("expected %d held packets released, got %d", maxHeldPerFlow, len(got))
	}
	for i, p := range got {
		if p[len(p)-1] != byte(i) {
			t.Errorf("released packet %d carries payload %d: order lost", i, p[len(p)-1])
		}
	}
	if !rd.check(udpPacket(5555, net.IPv4(1, 1, 1, 1), 9)) {
		t.Error("expected allow once the flow is judged")
	}
	if n := f.calls.Load(); n != 1 {
		t.Errorf("expected one filter call for the flow, got %d", n)
	}
}

func TestDeniedHeldPacketsDropped(t *testing.T) {
	f := &countingFilter{denySrcPort: 4444, gate: make(chan struct{})}
	rd := install(t, f)

	rd.check(udpPacket(4444, net.IPv4(1, 1, 1, 1), 0))
	rd.check(udpPacket(4444, net.IPv4(1, 1, 1, 1), 1))
	close(f.gate)
	rd.settle(t)
	if n := len(rd.r.released()); n != 0 {
		t.Errorf("expected held packets of a denied flow to be dropped, %d released", n)
	}
}

// A packet held longer than maxHoldTime is dropped when the verdict arrives;
// a later one of the same flow is still sent.
func TestHoldTimeLimit(t *testing.T) {
	f := &countingFilter{denySrcPort: -1, gate: make(chan struct{})}
	rd := install(t, f)

	rd.check(udpPacket(5555, net.IPv4(1, 1, 1, 1), 0))
	advanceClock(maxHoldTime + time.Millisecond)
	rd.check(udpPacket(5555, net.IPv4(1, 1, 1, 1), 1))
	close(f.gate)
	rd.settle(t)

	got := rd.r.released()
	if len(got) != 1 || got[0][len(got[0])-1] != 1 {
		t.Errorf("expected only the recent packet to be released, got %d", len(got))
	}
}

// Held packets are bounded in bytes as well as in count.
func TestHeldBytesLimit(t *testing.T) {
	f := &countingFilter{denySrcPort: -1, gate: make(chan struct{})}
	rd := install(t, f)

	const size = 64 << 10
	fit := maxHeldBytes / (size + 25)
	for i := 0; i < fit+5; i++ {
		p := append(udpPacket(2000+i, net.IPv4(1, 1, 1, 1), 0), make([]byte, size)...)
		rd.check(p)
	}
	rd.g.s.mu.Lock()
	held := rd.g.s.heldBytes
	rd.g.s.mu.Unlock()
	if held > maxHeldBytes {
		t.Errorf("held %d bytes, limit %d", held, maxHeldBytes)
	}
	close(f.gate)
	rd.settle(t)
	if n := int(f.calls.Load()); n != fit {
		t.Errorf("expected %d flows to be held and judged, got %d", fit, n)
	}
}

// With the pending table full, new flows are dropped without asking the filter,
// while flows already judged keep passing.
func TestPendingTableFull(t *testing.T) {
	f := &countingFilter{denySrcPort: -1}
	rd := install(t, f)
	established := udpPacket(1000, net.IPv4(1, 1, 1, 1), 0)
	if !rd.verdict(t, established) {
		t.Fatal("expected allow for the established flow")
	}

	f.gate = make(chan struct{})
	for i := 0; i < maxPendingFlows; i++ {
		rd.check(udpPacket(2000+i, net.IPv4(1, 1, 1, 1), 0))
	}
	for i := 0; i < 10; i++ {
		if rd.check(udpPacket(9000+i, net.IPv4(1, 1, 1, 1), 0)) {
			t.Fatal("a new flow passed while the pending table was full")
		}
	}
	if !rd.check(established) {
		t.Error("an established flow was dropped while the pending table was full")
	}
	close(f.gate)
	rd.settle(t)

	if n := f.calls.Load(); n != 1+maxPendingFlows {
		t.Errorf("expected %d filter calls, got %d: flows past the limit must not be asked", 1+maxPendingFlows, n)
	}
	if n := len(rd.r.released()); n != 1+maxPendingFlows {
		t.Errorf("expected %d packets released, got %d", 1+maxPendingFlows, n)
	}
	// A flow dropped for lack of room is not cached, so it is judged next time.
	if !rd.verdict(t, udpPacket(9000, net.IPv4(1, 1, 1, 1), 0)) {
		t.Error("a flow dropped for lack of room must be judged once there is room")
	}
}

// Set installs a filter together with fresh state: nothing the old filter
// decided survives the swap.
func TestSetStartsWithEmptyCache(t *testing.T) {
	rd := install(t, &countingFilter{denySrcPort: -1})
	p := udpPacket(5555, net.IPv4(1, 1, 1, 1), 0)
	if !rd.verdict(t, p) {
		t.Fatal("expected allow under the first filter")
	}
	second := &countingFilter{denySrcPort: 5555}
	Set(second)
	if rd.verdict(t, p) {
		t.Error("the new filter inherited the old filter's verdict")
	}
	if n := second.calls.Load(); n != 1 {
		t.Errorf("expected the new filter to be asked once, got %d", n)
	}
}

// A verdict that arrives after Set has replaced its filter sends nothing.
func TestLateVerdictAfterReplaceDropped(t *testing.T) {
	f := &countingFilter{denySrcPort: -1, gate: make(chan struct{})}
	rd := install(t, f)
	rd.check(udpPacket(5555, net.IPv4(1, 1, 1, 1), 0))
	for f.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	Set(nil)
	close(f.gate)
	time.Sleep(50 * time.Millisecond)
	if n := len(rd.r.released()); n != 0 {
		t.Errorf("%d packets held for a replaced filter were released", n)
	}
}

func TestSetNilStopsWorkers(t *testing.T) {
	Set(nil)
	time.Sleep(10 * time.Millisecond)
	before := runtime.NumGoroutine()
	Set(&countingFilter{denySrcPort: -1})
	if n := runtime.NumGoroutine(); n < before+workers {
		t.Fatalf("expected %d workers to start, goroutines went %d -> %d", workers, before, n)
	}
	Set(nil)
	for deadline := time.Now().Add(5 * time.Second); runtime.NumGoroutine() > before; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("workers still running: %d goroutines, %d before", runtime.NumGoroutine(), before)
		}
	}
}

// --- benchmarks: the cost the hook adds per packet ---

func benchPacket() []byte { return tcpPacket(5555, 0x10) } // an established-connection ACK

// The disabled path: what every non-Android build would pay if it were not
// compiled out, and what an Android build pays with the feature off.
func BenchmarkAllowOutboundPacketNoFilter(b *testing.B) {
	Set(nil)
	p := benchPacket()
	var rd reader
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !rd.check(p) {
			b.Fatal("unexpected deny")
		}
	}
}

// The common case with the feature on: a packet of a connection already judged.
func BenchmarkAllowOutboundPacketEstablishedTCP(b *testing.B) {
	rd := install(b, &countingFilter{denySrcPort: -1})
	p := benchPacket()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !rd.check(p) {
			b.Fatal("unexpected deny")
		}
	}
}

// A UDP packet of a flow whose verdict is cached: parse plus a cache hit.
func BenchmarkAllowOutboundPacketCachedUDP(b *testing.B) {
	rd := install(b, &countingFilter{denySrcPort: -1})
	p := ipv4Packet(ipProtoUDP, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 5555, 443)
	if !rd.verdict(b, p) {
		b.Fatal("unexpected deny")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !rd.check(p) {
			b.Fatal("unexpected deny")
		}
	}
}

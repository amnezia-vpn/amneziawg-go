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

// install sets f and returns the Releaser to pass with packets.
func install(t testing.TB, f PacketFilter) *recorder {
	Set(f)
	t.Cleanup(func() { Set(nil) })
	return &recorder{}
}

// settle waits until the workers have judged every pending flow.
func settle(t testing.TB) {
	h := current.Load()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		h.mu.Lock()
		waiting := h.waiting
		h.mu.Unlock()
		if waiting == 0 {
			return
		}
	}
	t.Fatal("pending flows were not judged in time")
}

// verdict returns what the filter decided for p's flow: the first packet is held,
// the next one after the verdict gets it directly.
func verdict(t testing.TB, p []byte, r Releaser) bool {
	if AllowOutboundPacket(p, r) {
		return true
	}
	settle(t)
	return AllowOutboundPacket(p, r)
}

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
	p := ipv4Packet(ipProtoTCP, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 4444, 443)
	if !AllowOutboundPacket(p, nil) {
		t.Error("expected allow when no filter installed")
	}
}

func TestAllowDenyAndCache(t *testing.T) {
	f := &countingFilter{denySrcPort: 4444}
	r := install(t, f)

	denied := udpPacket(4444, net.IPv4(1, 1, 1, 1), 0)
	allowed := udpPacket(5555, net.IPv4(1, 1, 1, 1), 0)

	if verdict(t, denied, r) {
		t.Error("expected deny for blocked source port")
	}
	if !verdict(t, allowed, r) {
		t.Error("expected allow for unblocked source port")
	}
	if got := r.released(); len(got) != 1 || !bytes.Equal(got[0], allowed) {
		t.Errorf("expected the held packet of the allowed flow alone to be released, got %d", len(got))
	}
	// Repeat: decisions must come from cache, not new filter calls.
	callsBefore := f.calls.Load()
	for i := 0; i < 5; i++ {
		if AllowOutboundPacket(denied, r) || !AllowOutboundPacket(allowed, r) {
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
	r := install(t, f)

	if !verdict(t, udpPacket(40000, net.IPv4(1, 1, 1, 1), 0), r) {
		t.Fatal("expected allow for the first destination")
	}
	if verdict(t, udpPacket(40000, net.IPv4(2, 2, 2, 2), 0), r) {
		t.Error("a packet from the same port to another destination passed on the old verdict")
	}
	if n := f.calls.Load(); n != 2 {
		t.Errorf("expected the filter to be asked once per destination, got %d calls", n)
	}
}

// The filter sees IPv6 addresses as they are, not as IPv4-mapped ones.
func TestIPv6FlowJudged(t *testing.T) {
	f := &countingFilter{denySrcPort: -1, denyDstIP: "2001:db8::2"}
	r := install(t, f)
	p := make([]byte, 40+8)
	p[0] = 0x60
	p[6] = ipProtoUDP
	copy(p[ipv6OffsetSrc:], net.ParseIP("fd00::2"))
	copy(p[ipv6OffsetDst:], net.ParseIP("2001:db8::2"))
	p[40], p[41], p[42], p[43] = 0x15, 0xb3, 0x01, 0xbb
	if verdict(t, p, r) {
		t.Error("expected deny for the IPv6 destination")
	}
}

func TestUnresolvablePacketsDroppedWhileFiltering(t *testing.T) {
	r := install(t, &countingFilter{denySrcPort: -1})
	// ICMP echo can be sent from an unprivileged ping socket bound to tun0.
	icmp := ipv4Packet(1, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 0, 0)
	if AllowOutboundPacket(icmp, r) {
		t.Error("ICMP must be dropped while a filter is installed")
	}
	frag := ipv4Packet(ipProtoUDP, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 5555, 443)
	frag[6] = 0x20 // more fragments
	if AllowOutboundPacket(frag, r) {
		t.Error("IPv4 fragments must be dropped while a filter is installed")
	}
	settle(t)
	if n := len(r.released()); n != 0 {
		t.Errorf("unresolvable packets must not be held, %d were released", n)
	}
	Set(nil)
	if !AllowOutboundPacket(icmp, r) {
		t.Error("ICMP must pass when no filter is installed")
	}
}

func TestTCPJudgedOnlyOnSYN(t *testing.T) {
	f := &countingFilter{denySrcPort: 4444}
	r := install(t, f)

	const ack, fin, synAck = 0x10, 0x11, 0x12
	// Packets of an established or closing connection are not judged, even on a
	// denied port: its SYN already passed, or the connection never existed.
	for _, flags := range []byte{ack, fin} {
		if !AllowOutboundPacket(tcpPacket(4444, flags), r) {
			t.Errorf("flags %#x: expected pass-through without SYN", flags)
		}
	}
	if n := f.calls.Load(); n != 0 {
		t.Errorf("expected no filter calls without SYN, got %d", n)
	}
	if verdict(t, tcpPacket(4444, tcpFlagSYN), r) {
		t.Error("expected deny for SYN on blocked source port")
	}
	if AllowOutboundPacket(tcpPacket(4444, synAck), r) {
		t.Error("expected deny for SYN-ACK on blocked source port (cached)")
	}
	if !verdict(t, tcpPacket(5555, tcpFlagSYN), r) {
		t.Error("expected allow for SYN on unblocked source port")
	}
}

// Packets of a flow being judged wait for the verdict, a few of them, and leave
// in the order they were read.
func TestHeldPacketsReleasedInOrder(t *testing.T) {
	f := &countingFilter{denySrcPort: -1, gate: make(chan struct{})}
	r := install(t, f)

	for i := 0; i < maxHeldPerFlow+2; i++ {
		if AllowOutboundPacket(udpPacket(5555, net.IPv4(1, 1, 1, 1), byte(i)), r) {
			t.Fatalf("packet %d passed before its flow was judged", i)
		}
	}
	if n := len(r.released()); n != 0 {
		t.Fatalf("%d packets released before the verdict", n)
	}
	close(f.gate)
	settle(t)

	got := r.released()
	if len(got) != maxHeldPerFlow {
		t.Fatalf("expected %d held packets released, got %d", maxHeldPerFlow, len(got))
	}
	for i, p := range got {
		if p[len(p)-1] != byte(i) {
			t.Errorf("released packet %d carries payload %d: order lost", i, p[len(p)-1])
		}
	}
	if !AllowOutboundPacket(udpPacket(5555, net.IPv4(1, 1, 1, 1), 9), r) {
		t.Error("expected allow once the flow is judged")
	}
	if n := f.calls.Load(); n != 1 {
		t.Errorf("expected one filter call for the flow, got %d", n)
	}
}

func TestDeniedHeldPacketsDropped(t *testing.T) {
	f := &countingFilter{denySrcPort: 4444, gate: make(chan struct{})}
	r := install(t, f)

	AllowOutboundPacket(udpPacket(4444, net.IPv4(1, 1, 1, 1), 0), r)
	AllowOutboundPacket(udpPacket(4444, net.IPv4(1, 1, 1, 1), 1), r)
	close(f.gate)
	settle(t)
	if n := len(r.released()); n != 0 {
		t.Errorf("expected held packets of a denied flow to be dropped, %d released", n)
	}
}

// With the pending table full, new flows are dropped without asking the filter,
// while flows already judged keep passing.
func TestPendingTableFull(t *testing.T) {
	f := &countingFilter{denySrcPort: -1}
	r := install(t, f)
	established := udpPacket(1000, net.IPv4(1, 1, 1, 1), 0)
	if !verdict(t, established, r) {
		t.Fatal("expected allow for the established flow")
	}

	f.gate = make(chan struct{})
	for i := 0; i < maxPendingFlows; i++ {
		AllowOutboundPacket(udpPacket(2000+i, net.IPv4(1, 1, 1, 1), 0), r)
	}
	for i := 0; i < 10; i++ {
		if AllowOutboundPacket(udpPacket(9000+i, net.IPv4(1, 1, 1, 1), 0), r) {
			t.Fatal("a new flow passed while the pending table was full")
		}
	}
	if !AllowOutboundPacket(established, r) {
		t.Error("an established flow was dropped while the pending table was full")
	}
	close(f.gate)
	settle(t)

	if n := f.calls.Load(); n != 1+maxPendingFlows {
		t.Errorf("expected %d filter calls, got %d: flows past the limit must not be asked", 1+maxPendingFlows, n)
	}
	if n := len(r.released()); n != 1+maxPendingFlows {
		t.Errorf("expected %d packets released, got %d", 1+maxPendingFlows, n)
	}
	// A flow dropped for lack of room is not cached, so it is judged next time.
	if !verdict(t, udpPacket(9000, net.IPv4(1, 1, 1, 1), 0), r) {
		t.Error("a flow dropped for lack of room must be judged once there is room")
	}
}

// Set installs a filter together with its own cache: nothing the old filter
// decided survives the swap.
func TestSetStartsWithEmptyCache(t *testing.T) {
	r := install(t, &countingFilter{denySrcPort: -1})
	p := udpPacket(5555, net.IPv4(1, 1, 1, 1), 0)
	if !verdict(t, p, r) {
		t.Fatal("expected allow under the first filter")
	}
	second := &countingFilter{denySrcPort: 5555}
	Set(second)
	if verdict(t, p, r) {
		t.Error("the new filter inherited the old filter's verdict")
	}
	if n := second.calls.Load(); n != 1 {
		t.Errorf("expected the new filter to be asked once, got %d", n)
	}
}

// Packets held for a filter that has been replaced are dropped, whatever it answers.
func TestHeldPacketsDroppedOnReplace(t *testing.T) {
	f := &countingFilter{denySrcPort: -1, gate: make(chan struct{})}
	r := install(t, f)
	AllowOutboundPacket(udpPacket(5555, net.IPv4(1, 1, 1, 1), 0), r)
	for f.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	Set(nil)
	close(f.gate)
	time.Sleep(50 * time.Millisecond)
	if n := len(r.released()); n != 0 {
		t.Errorf("%d packets held for a replaced filter were released", n)
	}
}

func TestSetNilStopsWorkers(t *testing.T) {
	Set(nil)
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
	r := &recorder{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !AllowOutboundPacket(p, r) {
			b.Fatal("unexpected deny")
		}
	}
}

// The common case with the feature on: a packet of a connection already judged.
func BenchmarkAllowOutboundPacketEstablishedTCP(b *testing.B) {
	r := install(b, &countingFilter{denySrcPort: -1})
	p := benchPacket()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !AllowOutboundPacket(p, r) {
			b.Fatal("unexpected deny")
		}
	}
}

// A UDP packet of a flow whose verdict is cached: parse plus a cache hit.
func BenchmarkAllowOutboundPacketCachedUDP(b *testing.B) {
	r := install(b, &countingFilter{denySrcPort: -1})
	p := ipv4Packet(ipProtoUDP, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 5555, 443)
	if !verdict(b, p, r) {
		b.Fatal("unexpected deny")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !AllowOutboundPacket(p, r) {
			b.Fatal("unexpected deny")
		}
	}
}

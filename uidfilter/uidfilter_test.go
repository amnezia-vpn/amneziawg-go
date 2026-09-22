package uidfilter

import (
	"net"
	"testing"
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

// countingFilter denies a specific source port and records call count.
type countingFilter struct {
	denySrcPort int
	calls       int
}

func (f *countingFilter) Allow(network, srcIP string, srcPort int, dstIP string, dstPort int) bool {
	f.calls++
	return srcPort != f.denySrcPort
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
	if !AllowOutboundPacket(p) {
		t.Error("expected allow when no filter installed")
	}
}

func TestAllowDenyAndCache(t *testing.T) {
	f := &countingFilter{denySrcPort: 4444}
	Set(f)
	t.Cleanup(func() { Set(nil) })

	denied := ipv4Packet(ipProtoTCP, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 4444, 443)
	allowed := ipv4Packet(ipProtoTCP, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 5555, 443)

	if AllowOutboundPacket(denied) {
		t.Error("expected deny for blocked source port")
	}
	if !AllowOutboundPacket(allowed) {
		t.Error("expected allow for unblocked source port")
	}
	// Repeat: decisions must come from cache, not new filter calls.
	callsBefore := f.calls
	for i := 0; i < 5; i++ {
		AllowOutboundPacket(denied)
		AllowOutboundPacket(allowed)
	}
	if f.calls != callsBefore {
		t.Errorf("expected cache hits (no extra filter calls), got %d extra", f.calls-callsBefore)
	}
}

func TestUnresolvablePacketsDroppedWhileFiltering(t *testing.T) {
	Set(&countingFilter{denySrcPort: -1})
	t.Cleanup(func() { Set(nil) })
	// ICMP echo can be sent from an unprivileged ping socket bound to tun0.
	icmp := ipv4Packet(1, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 0, 0)
	if AllowOutboundPacket(icmp) {
		t.Error("ICMP must be dropped while a filter is installed")
	}
	frag := ipv4Packet(ipProtoUDP, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 5555, 443)
	frag[6] = 0x20 // more fragments
	if AllowOutboundPacket(frag) {
		t.Error("IPv4 fragments must be dropped while a filter is installed")
	}
	Set(nil)
	if !AllowOutboundPacket(icmp) {
		t.Error("ICMP must pass when no filter is installed")
	}
}

func TestTCPJudgedOnlyOnSYN(t *testing.T) {
	f := &countingFilter{denySrcPort: 4444}
	Set(f)
	t.Cleanup(func() { Set(nil) })

	const ack, fin, synAck = 0x10, 0x11, 0x12
	// Packets of an established or closing connection are not judged, even on a
	// denied port: its SYN already passed, or the connection never existed.
	for _, flags := range []byte{ack, fin} {
		if !AllowOutboundPacket(tcpPacket(4444, flags)) {
			t.Errorf("flags %#x: expected pass-through without SYN", flags)
		}
	}
	if f.calls != 0 {
		t.Errorf("expected no filter calls without SYN, got %d", f.calls)
	}
	if AllowOutboundPacket(tcpPacket(4444, tcpFlagSYN)) {
		t.Error("expected deny for SYN on blocked source port")
	}
	if AllowOutboundPacket(tcpPacket(4444, synAck)) {
		t.Error("expected deny for SYN-ACK on blocked source port (cached)")
	}
	if !AllowOutboundPacket(tcpPacket(5555, tcpFlagSYN)) {
		t.Error("expected allow for SYN on unblocked source port")
	}
}

// --- benchmarks: the cost the hook adds per packet ---

func benchPacket() []byte { return tcpPacket(5555, 0x10) } // an established-connection ACK

// The disabled path: what every non-Android build would pay if it were not
// compiled out, and what an Android build pays with the feature off.
func BenchmarkAllowOutboundPacketNoFilter(b *testing.B) {
	Set(nil)
	p := benchPacket()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !AllowOutboundPacket(p) {
			b.Fatal("unexpected deny")
		}
	}
}

// The common case with the feature on: a packet of a connection already judged.
func BenchmarkAllowOutboundPacketEstablishedTCP(b *testing.B) {
	Set(&countingFilter{denySrcPort: -1})
	b.Cleanup(func() { Set(nil) })
	p := benchPacket()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !AllowOutboundPacket(p) {
			b.Fatal("unexpected deny")
		}
	}
}

// A UDP packet of a flow whose verdict is cached: parse plus a cache hit.
func BenchmarkAllowOutboundPacketCachedUDP(b *testing.B) {
	Set(&countingFilter{denySrcPort: -1})
	b.Cleanup(func() { Set(nil) })
	p := ipv4Packet(ipProtoUDP, net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1), 5555, 443)
	AllowOutboundPacket(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !AllowOutboundPacket(p) {
			b.Fatal("unexpected deny")
		}
	}
}

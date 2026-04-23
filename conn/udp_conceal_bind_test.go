package conn

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/conceal"
)

func TestConcealBindUDPPipelineOrder(t *testing.T) {
	bind := NewConcealBind(&fakePacketBind{batchSize: 4})
	bind.SetMasqueradeOpts(conceal.MasqueradeOpts{
		RulesIn:  mustParseRules(t, "<dz be 2><d>"),
		RulesOut: mustParseRules(t, "<dz be 2><d>"),
	})
	bind.SetFramedOpts(conceal.FramedOpts{H1: mustHeader(t, "777")})
	bind.SetPreludeOpts(conceal.PreludeOpts{
		RulesArr: [5]conceal.Rules{mustParseRules(t, "<b 0xaabb>")},
	})

	got := bind.udpConcealPipeline().names()
	want := []string{"masquerade", "framed", "prelude"}
	if !slices.Equal(got, want) {
		t.Fatalf("udp pipeline = %v, want %v", got, want)
	}
}

func TestConcealBindNoOpWithoutOpts(t *testing.T) {
	inner := &fakePacketBind{
		batchSize: 3,
		recvBatches: []fakeRecvBatch{
			{
				packets: [][]byte{makeInitiationPacket(), makeTransportPacket()},
				eps: []Endpoint{
					&fakePacketEndpoint{addr: netip.MustParseAddrPort("127.0.0.1:51820")},
					&fakePacketEndpoint{addr: netip.MustParseAddrPort("127.0.0.1:51820")},
				},
			},
		},
	}
	bind := NewConcealBind(inner)

	endpoint, err := bind.ParseEndpoint("127.0.0.1:51820")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	initiation := makeInitiationPacket()
	transport := makeTransportPacket()
	if err := bind.Send([][]byte{initiation, transport}, endpoint); err != nil {
		t.Fatalf("send: %v", err)
	}

	if len(inner.sendCalls) != 1 {
		t.Fatalf("send calls = %d, want 1", len(inner.sendCalls))
	}
	if got := sendCallBatchLengths(inner.sendCalls); !slices.Equal(got, []int{2}) {
		t.Fatalf("send batch lengths = %v, want [2]", got)
	}
	if got := inner.sendCalls[0].packets; !slices.EqualFunc(got, [][]byte{initiation, transport}, bytes.Equal) {
		t.Fatalf("sent packets changed on no-op path")
	}
	if got := bind.BatchSize(); got != 3 {
		t.Fatalf("batch size = %d, want 3", got)
	}

	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	bufs := [][]byte{make([]byte, 256), make([]byte, 256), make([]byte, 256)}
	sizes := make([]int, 3)
	eps := make([]Endpoint, 3)

	n, err := fns[0](bufs, sizes, eps)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if n != 2 {
		t.Fatalf("received count = %d, want 2", n)
	}
	if !bytes.Equal(bufs[0][:sizes[0]], initiation) {
		t.Fatalf("initiation changed on no-op path")
	}
	if !bytes.Equal(bufs[1][:sizes[1]], transport) {
		t.Fatalf("transport changed on no-op path")
	}
}

func TestConcealBindSendBatchesActivePipeline(t *testing.T) {
	inner := &fakePacketBind{batchSize: 3}
	bind := NewConcealBind(inner)
	bind.SetFramedOpts(conceal.FramedOpts{
		H1: mustHeader(t, "777"),
		H2: mustHeader(t, "778"),
		H4: mustHeader(t, "779"),
	})

	endpoint, err := bind.ParseEndpoint("127.0.0.1:51820")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	initiation := makeInitiationPacket()
	transport := makeTransportPacket()
	response := makeResponsePacket()
	if err := bind.Send([][]byte{initiation, transport, response}, endpoint); err != nil {
		t.Fatalf("send: %v", err)
	}

	if got := sendCallBatchLengths(inner.sendCalls); !slices.Equal(got, []int{3}) {
		t.Fatalf("send batch lengths = %v, want [3]", got)
	}

	wirePackets := flattenSendCalls(inner.sendCalls)
	if len(wirePackets) != 3 {
		t.Fatalf("wire packet count = %d, want 3", len(wirePackets))
	}
	if got := wireHeader(t, wirePackets[0]); got != 777 {
		t.Fatalf("wire packet 0 header = %d, want 777", got)
	}
	if got := wireHeader(t, wirePackets[1]); got != 779 {
		t.Fatalf("wire packet 1 header = %d, want 779", got)
	}
	if got := wireHeader(t, wirePackets[2]); got != 778 {
		t.Fatalf("wire packet 2 header = %d, want 778", got)
	}
}

func TestConcealBindSendBatchesPreludeInWireOrder(t *testing.T) {
	inner := &fakePacketBind{batchSize: 3}
	bind := NewConcealBind(inner)
	bind.SetFramedOpts(conceal.FramedOpts{
		H1: mustHeader(t, "777"),
		H4: mustHeader(t, "779"),
	})
	bind.SetPreludeOpts(conceal.PreludeOpts{
		Jc:   1,
		Jmin: 3,
		Jmax: 3,
		RulesArr: [5]conceal.Rules{
			mustParseRules(t, "<b 0xaabb>"),
		},
	})

	endpoint, err := bind.ParseEndpoint("127.0.0.1:51820")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	firstInitiation := makeInitiationPacket()
	transport := makeTransportPacket()
	secondInitiation := makeInitiationPacket()
	if err := bind.Send([][]byte{firstInitiation, transport, secondInitiation}, endpoint); err != nil {
		t.Fatalf("send: %v", err)
	}

	if got := sendCallBatchLengths(inner.sendCalls); !slices.Equal(got, []int{3, 3, 1}) {
		t.Fatalf("send batch lengths = %v, want [3 3 1]", got)
	}

	wirePackets := flattenSendCalls(inner.sendCalls)
	if len(wirePackets) != 7 {
		t.Fatalf("wire packet count = %d, want 7", len(wirePackets))
	}
	if !bytes.Equal(wirePackets[0], []byte{0xaa, 0xbb}) {
		t.Fatalf("wire packet 0 prelude = %x, want aabb", wirePackets[0])
	}
	if len(wirePackets[1]) != 3 {
		t.Fatalf("wire packet 1 junk len = %d, want 3", len(wirePackets[1]))
	}
	if got := wireHeader(t, wirePackets[2]); got != 777 {
		t.Fatalf("wire packet 2 header = %d, want 777", got)
	}
	if got := wireHeader(t, wirePackets[3]); got != 779 {
		t.Fatalf("wire packet 3 header = %d, want 779", got)
	}
	if !bytes.Equal(wirePackets[4], []byte{0xaa, 0xbb}) {
		t.Fatalf("wire packet 4 prelude = %x, want aabb", wirePackets[4])
	}
	if len(wirePackets[5]) != 3 {
		t.Fatalf("wire packet 5 junk len = %d, want 3", len(wirePackets[5]))
	}
	if got := wireHeader(t, wirePackets[6]); got != 777 {
		t.Fatalf("wire packet 6 header = %d, want 777", got)
	}
}

func TestConcealBindSendAndReceive(t *testing.T) {
	senderInner := &fakePacketBind{batchSize: 4}
	sender := newTestConcealBind(t, senderInner)

	endpoint, err := sender.ParseEndpoint("127.0.0.1:51820")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	initiation := makeInitiationPacket()
	transport := makeTransportPacket()
	if err := sender.Send([][]byte{initiation, transport}, endpoint); err != nil {
		t.Fatalf("send: %v", err)
	}

	wirePackets := flattenSendCalls(senderInner.sendCalls)
	if len(wirePackets) != 4 {
		t.Fatalf("wire packet count = %d, want 4", len(wirePackets))
	}
	if !bytes.Equal(wirePackets[0], []byte{0xaa, 0xbb}) {
		t.Fatalf("wire prelude decoy = %x, want aabb", wirePackets[0])
	}
	if len(wirePackets[1]) != 3 {
		t.Fatalf("wire junk len = %d, want 3", len(wirePackets[1]))
	}

	receiverInner := &fakePacketBind{
		batchSize: 4,
		recvBatches: []fakeRecvBatch{
			{
				packets: wirePackets,
				eps: []Endpoint{
					endpoint,
					endpoint,
					endpoint,
					endpoint,
				},
			},
		},
	}
	receiver := newTestConcealBind(t, receiverInner)

	fns, _, err := receiver.Open(0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	bufs := [][]byte{
		make([]byte, 256),
		make([]byte, 256),
		make([]byte, 256),
		make([]byte, 256),
	}
	sizes := make([]int, 4)
	eps := make([]Endpoint, 4)

	n, err := fns[0](bufs, sizes, eps)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if n != 4 {
		t.Fatalf("received count = %d, want 4", n)
	}
	if got := sizes[:n]; !slices.Equal(got, []int{0, 0, len(initiation), len(transport)}) {
		t.Fatalf("sizes = %v, want [0 0 %d %d]", got, len(initiation), len(transport))
	}
	if eps[0] != nil || eps[1] != nil {
		t.Fatalf("dropped endpoints = %v %v, want nil nil", eps[0], eps[1])
	}
	if !bytes.Equal(bufs[2][:sizes[2]], initiation) {
		t.Fatalf("decoded initiation mismatch")
	}
	if !bytes.Equal(bufs[3][:sizes[3]], transport) {
		t.Fatalf("decoded transport mismatch")
	}
	if got := eps[2].DstToString(); got != endpoint.DstToString() {
		t.Fatalf("endpoint[2] = %q, want %q", got, endpoint.DstToString())
	}
	if got := eps[3].DstToString(); got != endpoint.DstToString() {
		t.Fatalf("endpoint[3] = %q, want %q", got, endpoint.DstToString())
	}
}

func TestConcealBindReceivePreservesIndicesForMixedBatch(t *testing.T) {
	senderInner := &fakePacketBind{batchSize: 4}
	sender := newTestConcealBind(t, senderInner)

	endpoint, err := sender.ParseEndpoint("127.0.0.1:51820")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	initiation := makeInitiationPacket()
	if err := sender.Send([][]byte{initiation}, endpoint); err != nil {
		t.Fatalf("send: %v", err)
	}

	wirePackets := flattenSendCalls(senderInner.sendCalls)
	if len(wirePackets) != 3 {
		t.Fatalf("wire packet count = %d, want 3", len(wirePackets))
	}

	receiverInner := &fakePacketBind{
		batchSize: 4,
		recvBatches: []fakeRecvBatch{
			{
				packets: [][]byte{wirePackets[0], wirePackets[2]},
				eps: []Endpoint{
					endpoint,
					endpoint,
				},
			},
		},
	}
	receiver := newTestConcealBind(t, receiverInner)

	fns, _, err := receiver.Open(0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	bufs := [][]byte{
		make([]byte, 256),
		make([]byte, 256),
	}
	sizes := make([]int, 2)
	eps := make([]Endpoint, 2)

	n, err := fns[0](bufs, sizes, eps)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if n != 2 {
		t.Fatalf("received count = %d, want 2", n)
	}
	if got := sizes[:n]; !slices.Equal(got, []int{0, len(initiation)}) {
		t.Fatalf("sizes = %v, want [0 %d]", got, len(initiation))
	}
	if eps[0] != nil {
		t.Fatalf("endpoint[0] = %v, want nil", eps[0])
	}
	if !bytes.Equal(bufs[0][:len(wirePackets[0])], wirePackets[0]) {
		t.Fatalf("slot 0 packet bytes changed unexpectedly")
	}
	if !bytes.Equal(bufs[1][:sizes[1]], initiation) {
		t.Fatalf("decoded initiation was not left in slot 1")
	}
	if got := eps[1].DstToString(); got != endpoint.DstToString() {
		t.Fatalf("endpoint[1] = %q, want %q", got, endpoint.DstToString())
	}
}

func TestConcealBindReceiveInvalidOnlyBatchReturnsZeroSizesWithoutRetry(t *testing.T) {
	senderInner := &fakePacketBind{batchSize: 4}
	sender := newTestConcealBind(t, senderInner)

	endpoint, err := sender.ParseEndpoint("127.0.0.1:51820")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	initiation := makeInitiationPacket()
	if err := sender.Send([][]byte{initiation}, endpoint); err != nil {
		t.Fatalf("send: %v", err)
	}

	wirePackets := flattenSendCalls(senderInner.sendCalls)
	if len(wirePackets) != 3 {
		t.Fatalf("wire packet count = %d, want 3", len(wirePackets))
	}

	receiverInner := &fakePacketBind{
		batchSize: 4,
		recvBatches: []fakeRecvBatch{
			{
				packets: wirePackets[:2],
				eps: []Endpoint{
					endpoint,
					endpoint,
				},
			},
			{
				packets: wirePackets[2:],
				eps: []Endpoint{
					endpoint,
				},
			},
		},
	}
	receiver := newTestConcealBind(t, receiverInner)

	fns, _, err := receiver.Open(0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	bufs := [][]byte{
		make([]byte, 256),
		make([]byte, 256),
		make([]byte, 256),
		make([]byte, 256),
	}
	sizes := make([]int, 4)
	eps := make([]Endpoint, 4)

	n, err := fns[0](bufs, sizes, eps)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if n != 2 {
		t.Fatalf("received count = %d, want 2", n)
	}
	if receiverInner.recvCalls != 1 {
		t.Fatalf("inner receive calls = %d, want 1", receiverInner.recvCalls)
	}
	if got := sizes[:n]; !slices.Equal(got, []int{0, 0}) {
		t.Fatalf("sizes = %v, want [0 0]", got)
	}
	if eps[0] != nil || eps[1] != nil {
		t.Fatalf("dropped endpoints = %v %v, want nil nil", eps[0], eps[1])
	}

	n, err = fns[0](bufs, sizes, eps)
	if err != nil {
		t.Fatalf("second receive: %v", err)
	}
	if n != 1 {
		t.Fatalf("second received count = %d, want 1", n)
	}
	if !bytes.Equal(bufs[0][:sizes[0]], initiation) {
		t.Fatalf("decoded initiation mismatch on second receive")
	}
	if got := eps[0].DstToString(); got != endpoint.DstToString() {
		t.Fatalf("endpoint[0] = %q, want %q", got, endpoint.DstToString())
	}
}

func TestConcealBindMasqueradePassThroughWithoutRulesOut(t *testing.T) {
	inner := &fakePacketBind{batchSize: 2}
	bind := NewConcealBind(inner)
	bind.SetMasqueradeOpts(conceal.MasqueradeOpts{
		RulesIn: mustParseRules(t, "<dz be 2><d>"),
	})

	endpoint, err := bind.ParseEndpoint("127.0.0.1:51820")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	transport := makeTransportPacket()
	if err := bind.Send([][]byte{transport}, endpoint); err != nil {
		t.Fatalf("send: %v", err)
	}
	wirePackets := flattenSendCalls(inner.sendCalls)
	if len(wirePackets) != 1 {
		t.Fatalf("wire packet count = %d, want 1", len(wirePackets))
	}
	if !bytes.Equal(wirePackets[0], transport) {
		t.Fatalf("half-duplex masquerade changed outbound packet")
	}
}

func newTestConcealBind(t *testing.T, inner *fakePacketBind) *ConcealBind {
	t.Helper()

	bind := NewConcealBind(inner)
	rules := mustParseRules(t, "<dz be 2><d>")
	bind.SetMasqueradeOpts(conceal.MasqueradeOpts{
		RulesIn:  rules,
		RulesOut: rules,
	})
	bind.SetFramedOpts(conceal.FramedOpts{
		H1: mustHeader(t, "777"),
		H4: mustHeader(t, "779"),
	})
	bind.SetPreludeOpts(conceal.PreludeOpts{
		Jc:   1,
		Jmin: 3,
		Jmax: 3,
		RulesArr: [5]conceal.Rules{
			mustParseRules(t, "<b 0xaabb>"),
		},
	})
	return bind
}

type fakePacketBind struct {
	batchSize   int
	recvBatches []fakeRecvBatch
	sendCalls   []fakeSendCall
	recvCalls   int
	openCalls   int
	closeCalls  int
}

type fakeRecvBatch struct {
	packets [][]byte
	eps     []Endpoint
	err     error
}

type fakeSendCall struct {
	packets  [][]byte
	endpoint Endpoint
}

func (b *fakePacketBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	b.openCalls++
	idx := 0
	return []ReceiveFunc{
		func(packets [][]byte, sizes []int, eps []Endpoint) (int, error) {
			b.recvCalls++
			if idx >= len(b.recvBatches) {
				return 0, net.ErrClosed
			}
			batch := b.recvBatches[idx]
			idx++
			for i, payload := range batch.packets {
				copy(packets[i], payload)
				sizes[i] = len(payload)
				eps[i] = batch.eps[i]
			}
			return len(batch.packets), batch.err
		},
	}, port, nil
}

func (b *fakePacketBind) Close() error {
	b.closeCalls++
	return nil
}

func (b *fakePacketBind) SetMark(mark uint32) error {
	return nil
}

func (b *fakePacketBind) Send(bufs [][]byte, ep Endpoint) error {
	packets := make([][]byte, 0, len(bufs))
	for _, buf := range bufs {
		packets = append(packets, bytes.Clone(buf))
	}
	b.sendCalls = append(b.sendCalls, fakeSendCall{
		packets:  packets,
		endpoint: ep,
	})
	return nil
}

func (b *fakePacketBind) ParseEndpoint(s string) (Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &fakePacketEndpoint{addr: addr}, nil
}

func (b *fakePacketBind) BatchSize() int {
	return b.batchSize
}

type fakePacketEndpoint struct {
	addr netip.AddrPort
}

func (e *fakePacketEndpoint) ClearSrc() {}

func (e *fakePacketEndpoint) SrcToString() string {
	return ""
}

func (e *fakePacketEndpoint) DstToString() string {
	return e.addr.String()
}

func (e *fakePacketEndpoint) DstToBytes() []byte {
	out, _ := e.addr.MarshalBinary()
	return out
}

func (e *fakePacketEndpoint) DstIP() netip.Addr {
	return e.addr.Addr()
}

func (e *fakePacketEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

func flattenSendCalls(calls []fakeSendCall) [][]byte {
	var out [][]byte
	for _, call := range calls {
		out = append(out, call.packets...)
	}
	return out
}

func sendCallBatchLengths(calls []fakeSendCall) []int {
	lengths := make([]int, 0, len(calls))
	for _, call := range calls {
		lengths = append(lengths, len(call.packets))
	}
	return lengths
}

func wireHeader(t *testing.T, packet []byte) uint32 {
	t.Helper()

	if len(packet) < 4 {
		t.Fatalf("wire packet len = %d, want at least 4", len(packet))
	}
	return binary.LittleEndian.Uint32(packet[:4])
}

var _ Bind = (*fakePacketBind)(nil)
var _ Endpoint = (*fakePacketEndpoint)(nil)

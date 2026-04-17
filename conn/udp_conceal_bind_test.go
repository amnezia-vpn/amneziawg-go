package conn

import (
	"bytes"
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
	if n != 2 {
		t.Fatalf("received count = %d, want 2", n)
	}
	if !bytes.Equal(bufs[0][:sizes[0]], initiation) {
		t.Fatalf("decoded initiation mismatch")
	}
	if !bytes.Equal(bufs[1][:sizes[1]], transport) {
		t.Fatalf("decoded transport mismatch")
	}
	if got := eps[0].DstToString(); got != endpoint.DstToString() {
		t.Fatalf("endpoint[0] = %q, want %q", got, endpoint.DstToString())
	}
	if got := eps[1].DstToString(); got != endpoint.DstToString() {
		t.Fatalf("endpoint[1] = %q, want %q", got, endpoint.DstToString())
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

var _ Bind = (*fakePacketBind)(nil)
var _ Endpoint = (*fakePacketEndpoint)(nil)

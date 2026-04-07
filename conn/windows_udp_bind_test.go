package conn

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/conceal"
)

func TestWindowsUDPBindUsesFastPathWithoutConceal(t *testing.T) {
	fast := &fakeWindowsUDPBind{batchSize: 7}
	fallback := &fakeWindowsUDPBind{batchSize: 3}
	bind := newWindowsUDPBind(fast, fakeUDPEndpointCodec{kind: "fast"}, fallback, fakeUDPEndpointCodec{kind: "fallback"})

	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if len(fns) != 1 {
		t.Fatalf("receive funcs = %d, want 1", len(fns))
	}
	if fast.openCalls != 1 {
		t.Fatalf("fast open calls = %d, want 1", fast.openCalls)
	}
	if fallback.openCalls != 0 {
		t.Fatalf("fallback open calls = %d, want 0", fallback.openCalls)
	}
	if got := bind.BatchSize(); got != 7 {
		t.Fatalf("batch size = %d, want 7", got)
	}
}

func TestWindowsUDPBindUsesFallbackWhenConcealEnabled(t *testing.T) {
	tests := []struct {
		name  string
		apply func(*windowsUDPBind)
	}{
		{
			name: "framed",
			apply: func(bind *windowsUDPBind) {
				bind.SetFramedOpts(conceal.FramedOpts{H1: mustHeader(t, "777")})
			},
		},
		{
			name: "prelude",
			apply: func(bind *windowsUDPBind) {
				bind.SetPreludeOpts(conceal.PreludeOpts{Jc: 1})
			},
		},
		{
			name: "masquerade",
			apply: func(bind *windowsUDPBind) {
				rules := mustParseRules(t, "<dz be 2><d>")
				bind.SetMasqueradeOpts(conceal.MasqueradeOpts{RulesIn: rules, RulesOut: rules})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fast := &fakeWindowsUDPBind{batchSize: 7}
			fallback := &fakeWindowsUDPBind{batchSize: 3}
			bind := newWindowsUDPBind(fast, fakeUDPEndpointCodec{kind: "fast"}, fallback, fakeUDPEndpointCodec{kind: "fallback"})

			tt.apply(bind)

			_, _, err := bind.Open(0)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if fast.openCalls != 0 {
				t.Fatalf("fast open calls = %d, want 0", fast.openCalls)
			}
			if fallback.openCalls != 1 {
				t.Fatalf("fallback open calls = %d, want 1", fallback.openCalls)
			}
			if got := bind.BatchSize(); got != 3 {
				t.Fatalf("batch size = %d, want 3", got)
			}
		})
	}
}

func TestWindowsUDPBindParsedEndpointSurvivesPathSwitch(t *testing.T) {
	fast := &fakeWindowsUDPBind{batchSize: 7}
	fallback := &fakeWindowsUDPBind{batchSize: 3}
	bind := newWindowsUDPBind(fast, fakeUDPEndpointCodec{kind: "fast"}, fallback, fakeUDPEndpointCodec{kind: "fallback"})

	endpoint, err := bind.ParseEndpoint("127.0.0.1:51820")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	if _, ok := endpoint.(*windowsUDPEndpoint); !ok {
		t.Fatalf("endpoint type = %T, want *windowsUDPEndpoint", endpoint)
	}

	if _, _, err := bind.Open(0); err != nil {
		t.Fatalf("open fast path: %v", err)
	}
	if err := bind.Send([][]byte{{0x01}}, endpoint); err != nil {
		t.Fatalf("send fast path: %v", err)
	}
	fastSent, ok := fast.sentEndpoints[0].(*fakeNativeEndpoint)
	if !ok {
		t.Fatalf("fast sent endpoint type = %T, want *fakeNativeEndpoint", fast.sentEndpoints[0])
	}
	if fastSent.kind != "fast" {
		t.Fatalf("fast endpoint kind = %q, want fast", fastSent.kind)
	}
	if got, want := fastSent.addr.String(), "127.0.0.1:51820"; got != want {
		t.Fatalf("fast endpoint addr = %q, want %q", got, want)
	}
	if err := bind.Close(); err != nil {
		t.Fatalf("close fast path: %v", err)
	}

	bind.SetFramedOpts(conceal.FramedOpts{H1: mustHeader(t, "777")})
	if _, _, err := bind.Open(0); err != nil {
		t.Fatalf("open fallback path: %v", err)
	}
	if err := bind.Send([][]byte{{0x02}}, endpoint); err != nil {
		t.Fatalf("send fallback path: %v", err)
	}
	fallbackSent, ok := fallback.sentEndpoints[0].(*fakeNativeEndpoint)
	if !ok {
		t.Fatalf("fallback sent endpoint type = %T, want *fakeNativeEndpoint", fallback.sentEndpoints[0])
	}
	if fallbackSent.kind != "fallback" {
		t.Fatalf("fallback endpoint kind = %q, want fallback", fallbackSent.kind)
	}
	if got, want := fallbackSent.addr.String(), "127.0.0.1:51820"; got != want {
		t.Fatalf("fallback endpoint addr = %q, want %q", got, want)
	}
}

func TestWindowsUDPBindNormalizesReceiveEndpoints(t *testing.T) {
	tests := []struct {
		name            string
		configure       func(*windowsUDPBind)
		receiveEndpoint Endpoint
	}{
		{
			name:      "fast",
			configure: func(*windowsUDPBind) {},
			receiveEndpoint: &fakeNativeEndpoint{
				kind: "fast",
				addr: netip.MustParseAddrPort("127.0.0.1:51820"),
			},
		},
		{
			name: "fallback",
			configure: func(bind *windowsUDPBind) {
				bind.SetPreludeOpts(conceal.PreludeOpts{Jc: 1})
			},
			receiveEndpoint: &fakeNativeEndpoint{
				kind: "fallback",
				addr: netip.MustParseAddrPort("127.0.0.1:51820"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fast := &fakeWindowsUDPBind{batchSize: 7}
			fallback := &fakeWindowsUDPBind{batchSize: 3}
			fast.receiveEndpoint = &fakeNativeEndpoint{kind: "fast", addr: netip.MustParseAddrPort("127.0.0.1:51820")}
			fallback.receiveEndpoint = &fakeNativeEndpoint{kind: "fallback", addr: netip.MustParseAddrPort("127.0.0.1:51820")}
			bind := newWindowsUDPBind(fast, fakeUDPEndpointCodec{kind: "fast"}, fallback, fakeUDPEndpointCodec{kind: "fallback"})

			tt.configure(bind)

			fns, _, err := bind.Open(0)
			if err != nil {
				t.Fatalf("open: %v", err)
			}

			bufs := [][]byte{make([]byte, 1)}
			sizes := make([]int, 1)
			eps := make([]Endpoint, 1)
			n, err := fns[0](bufs, sizes, eps)
			if err != nil {
				t.Fatalf("receive: %v", err)
			}
			if n != 1 {
				t.Fatalf("received packet count = %d, want 1", n)
			}
			got, ok := eps[0].(*windowsUDPEndpoint)
			if !ok {
				t.Fatalf("receive endpoint type = %T, want *windowsUDPEndpoint", eps[0])
			}
			if want := "127.0.0.1:51820"; got.addr.String() != want {
				t.Fatalf("receive endpoint addr = %q, want %q", got.addr.String(), want)
			}
		})
	}
}

func TestWindowsUDPBindPropagatesConcealOptsToFallback(t *testing.T) {
	fast := &fakeWindowsUDPBind{batchSize: 7}
	fallback := &fakeWindowsUDPBind{batchSize: 3}
	bind := newWindowsUDPBind(fast, fakeUDPEndpointCodec{kind: "fast"}, fallback, fakeUDPEndpointCodec{kind: "fallback"})

	framed := conceal.FramedOpts{H1: mustHeader(t, "777")}
	prelude := conceal.PreludeOpts{Jc: 1}
	rules := mustParseRules(t, "<dz be 2><d>")
	masquerade := conceal.MasqueradeOpts{RulesIn: rules, RulesOut: rules}

	bind.SetFramedOpts(framed)
	bind.SetPreludeOpts(prelude)
	bind.SetMasqueradeOpts(masquerade)

	if fallback.framedOpts.H1 == nil {
		t.Fatal("fallback framed opts were not propagated")
	}
	if fallback.preludeOpts.Jc != 1 {
		t.Fatalf("fallback prelude jc = %d, want 1", fallback.preludeOpts.Jc)
	}
	if fallback.masqueradeOpts.RulesIn == nil || fallback.masqueradeOpts.RulesOut == nil {
		t.Fatal("fallback masquerade opts were not propagated")
	}
}

type fakeWindowsUDPBind struct {
	openCalls       int
	closeCalls      int
	batchSize       int
	receiveEndpoint Endpoint
	sentEndpoints   []Endpoint

	framedOpts     conceal.FramedOpts
	preludeOpts    conceal.PreludeOpts
	masqueradeOpts conceal.MasqueradeOpts
}

func (b *fakeWindowsUDPBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	b.openCalls++
	return []ReceiveFunc{
		func(packets [][]byte, sizes []int, eps []Endpoint) (int, error) {
			sizes[0] = 1
			eps[0] = b.receiveEndpoint
			return 1, nil
		},
	}, port, nil
}

func (b *fakeWindowsUDPBind) Close() error {
	b.closeCalls++
	return nil
}

func (b *fakeWindowsUDPBind) SetMark(mark uint32) error {
	return nil
}

func (b *fakeWindowsUDPBind) Send(bufs [][]byte, ep Endpoint) error {
	b.sentEndpoints = append(b.sentEndpoints, ep)
	return nil
}

func (b *fakeWindowsUDPBind) ParseEndpoint(s string) (Endpoint, error) {
	return nil, errors.New("not implemented")
}

func (b *fakeWindowsUDPBind) BatchSize() int {
	return b.batchSize
}

func (b *fakeWindowsUDPBind) SetFramedOpts(opts conceal.FramedOpts) {
	b.framedOpts = opts
}

func (b *fakeWindowsUDPBind) SetPreludeOpts(opts conceal.PreludeOpts) {
	b.preludeOpts = opts
}

func (b *fakeWindowsUDPBind) SetMasqueradeOpts(opts conceal.MasqueradeOpts) {
	b.masqueradeOpts = opts
}

type fakeUDPEndpointCodec struct {
	kind string
}

func (c fakeUDPEndpointCodec) toEndpoint(addr netip.AddrPort) (Endpoint, error) {
	return &fakeNativeEndpoint{kind: c.kind, addr: addr}, nil
}

func (c fakeUDPEndpointCodec) fromEndpoint(endpoint Endpoint) (netip.AddrPort, error) {
	switch ep := endpoint.(type) {
	case *fakeNativeEndpoint:
		return ep.addr, nil
	case *windowsUDPEndpoint:
		return ep.addr, nil
	default:
		return netip.AddrPort{}, errors.New("unexpected endpoint type")
	}
}

type fakeNativeEndpoint struct {
	kind string
	addr netip.AddrPort
}

func (e *fakeNativeEndpoint) ClearSrc() {}

func (e *fakeNativeEndpoint) SrcToString() string {
	return ""
}

func (e *fakeNativeEndpoint) DstToString() string {
	return e.addr.String()
}

func (e *fakeNativeEndpoint) DstToBytes() []byte {
	out, _ := e.addr.MarshalBinary()
	return out
}

func (e *fakeNativeEndpoint) DstIP() netip.Addr {
	return e.addr.Addr()
}

func (e *fakeNativeEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

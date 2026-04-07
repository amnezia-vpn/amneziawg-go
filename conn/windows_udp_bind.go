package conn

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/conceal"
)

type udpEndpointCodec interface {
	toEndpoint(addr netip.AddrPort) (Endpoint, error)
	fromEndpoint(endpoint Endpoint) (netip.AddrPort, error)
}

type stdNetUDPEndpointCodec struct{}

func (stdNetUDPEndpointCodec) toEndpoint(addr netip.AddrPort) (Endpoint, error) {
	return &StdNetEndpoint{AddrPort: addr}, nil
}

func (stdNetUDPEndpointCodec) fromEndpoint(endpoint Endpoint) (netip.AddrPort, error) {
	switch ep := endpoint.(type) {
	case *StdNetEndpoint:
		return ep.AddrPort, nil
	case *windowsUDPEndpoint:
		return ep.addr, nil
	default:
		return netip.ParseAddrPort(endpoint.DstToString())
	}
}

type windowsUDPEndpoint struct {
	addr netip.AddrPort
}

func (e *windowsUDPEndpoint) ClearSrc() {}

func (e *windowsUDPEndpoint) SrcToString() string {
	return ""
}

func (e *windowsUDPEndpoint) DstToString() string {
	return e.addr.String()
}

func (e *windowsUDPEndpoint) DstToBytes() []byte {
	out, _ := e.addr.MarshalBinary()
	return out
}

func (e *windowsUDPEndpoint) DstIP() netip.Addr {
	return e.addr.Addr()
}

func (e *windowsUDPEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

type windowsUDPBind struct {
	mu sync.RWMutex

	fast          Bind
	fastCodec     udpEndpointCodec
	fallback      Bind
	fallbackCodec udpEndpointCodec

	active      Bind
	activeCodec udpEndpointCodec

	framedOpts     conceal.FramedOpts
	preludeOpts    conceal.PreludeOpts
	masqueradeOpts conceal.MasqueradeOpts
}

var (
	_ Bind                  = (*windowsUDPBind)(nil)
	_ Framable              = (*windowsUDPBind)(nil)
	_ Preludable            = (*windowsUDPBind)(nil)
	_ Masqueradable         = (*windowsUDPBind)(nil)
	_ BindSocketToInterface = (*windowsUDPBind)(nil)
)

func newWindowsUDPBind(fast Bind, fastCodec udpEndpointCodec, fallback Bind, fallbackCodec udpEndpointCodec) *windowsUDPBind {
	return &windowsUDPBind{
		fast:          fast,
		fastCodec:     fastCodec,
		fallback:      fallback,
		fallbackCodec: fallbackCodec,
	}
}

func (b *windowsUDPBind) selectedBindLocked() (Bind, udpEndpointCodec) {
	if hasMasquerade(b.masqueradeOpts) || hasFramed(b.framedOpts) || !b.preludeOpts.IsEmpty() {
		return b.fallback, b.fallbackCodec
	}
	return b.fast, b.fastCodec
}

func (b *windowsUDPBind) selectedBind() (Bind, udpEndpointCodec) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.selectedBindLocked()
}

func (b *windowsUDPBind) activeBind() (Bind, udpEndpointCodec) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.active != nil {
		return b.active, b.activeCodec
	}
	return b.selectedBindLocked()
}

func (b *windowsUDPBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	active, codec := b.selectedBind()

	recvFns, actualPort, err := active.Open(port)
	if err != nil {
		return nil, 0, err
	}

	b.mu.Lock()
	b.active = active
	b.activeCodec = codec
	b.mu.Unlock()

	wrapped := make([]ReceiveFunc, len(recvFns))
	for i, fn := range recvFns {
		wrapped[i] = b.wrapReceiveFn(fn, codec)
	}
	return wrapped, actualPort, nil
}

func (b *windowsUDPBind) Close() error {
	active, _ := b.activeBind()
	err := active.Close()

	b.mu.Lock()
	b.active = nil
	b.activeCodec = nil
	b.mu.Unlock()

	return err
}

func (b *windowsUDPBind) SetMark(mark uint32) error {
	active, _ := b.activeBind()
	return active.SetMark(mark)
}

func (b *windowsUDPBind) Send(bufs [][]byte, endpoint Endpoint) error {
	active, codec := b.activeBind()
	addr, err := b.endpointAddr(endpoint, codec)
	if err != nil {
		return err
	}
	native, err := codec.toEndpoint(addr)
	if err != nil {
		return err
	}
	return active.Send(bufs, native)
}

func (b *windowsUDPBind) ParseEndpoint(s string) (Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &windowsUDPEndpoint{addr: addr}, nil
}

func (b *windowsUDPBind) BatchSize() int {
	active, _ := b.activeBind()
	return active.BatchSize()
}

func (b *windowsUDPBind) SetFramedOpts(opts conceal.FramedOpts) {
	b.mu.Lock()
	b.framedOpts = opts
	b.mu.Unlock()

	if framable, ok := b.fast.(Framable); ok {
		framable.SetFramedOpts(opts)
	}
	if framable, ok := b.fallback.(Framable); ok {
		framable.SetFramedOpts(opts)
	}
}

func (b *windowsUDPBind) SetPreludeOpts(opts conceal.PreludeOpts) {
	b.mu.Lock()
	b.preludeOpts = opts
	b.mu.Unlock()

	if preludable, ok := b.fast.(Preludable); ok {
		preludable.SetPreludeOpts(opts)
	}
	if preludable, ok := b.fallback.(Preludable); ok {
		preludable.SetPreludeOpts(opts)
	}
}

func (b *windowsUDPBind) SetMasqueradeOpts(opts conceal.MasqueradeOpts) {
	b.mu.Lock()
	b.masqueradeOpts = opts
	b.mu.Unlock()

	if masqueradable, ok := b.fast.(Masqueradable); ok {
		masqueradable.SetMasqueradeOpts(opts)
	}
	if masqueradable, ok := b.fallback.(Masqueradable); ok {
		masqueradable.SetMasqueradeOpts(opts)
	}
}

func (b *windowsUDPBind) BindSocketToInterface4(interfaceIndex uint32, blackhole bool) error {
	active, _ := b.activeBind()
	if bindable, ok := active.(BindSocketToInterface); ok {
		return bindable.BindSocketToInterface4(interfaceIndex, blackhole)
	}
	return nil
}

func (b *windowsUDPBind) BindSocketToInterface6(interfaceIndex uint32, blackhole bool) error {
	active, _ := b.activeBind()
	if bindable, ok := active.(BindSocketToInterface); ok {
		return bindable.BindSocketToInterface6(interfaceIndex, blackhole)
	}
	return nil
}

func (b *windowsUDPBind) wrapReceiveFn(fn ReceiveFunc, codec udpEndpointCodec) ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []Endpoint) (int, error) {
		n, err := fn(packets, sizes, eps)
		for i := 0; i < n; i++ {
			if eps[i] == nil {
				continue
			}
			addr, convErr := codec.fromEndpoint(eps[i])
			if convErr != nil {
				if err == nil {
					err = convErr
				}
				continue
			}
			eps[i] = &windowsUDPEndpoint{addr: addr}
		}
		return n, err
	}
}

func (b *windowsUDPBind) endpointAddr(endpoint Endpoint, codec udpEndpointCodec) (netip.AddrPort, error) {
	switch ep := endpoint.(type) {
	case *windowsUDPEndpoint:
		return ep.addr, nil
	case *StdNetEndpoint:
		return ep.AddrPort, nil
	default:
		if codec != nil {
			if addr, err := codec.fromEndpoint(endpoint); err == nil {
				return addr, nil
			}
		}
		addr, err := netip.ParseAddrPort(endpoint.DstToString())
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("parse udp endpoint %T: %w", endpoint, err)
		}
		return addr, nil
	}
}

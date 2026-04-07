//go:build windows

package conn

import (
	"net/netip"
)

type winRingUDPEndpointCodec struct {
	parser Bind
}

func (c winRingUDPEndpointCodec) toEndpoint(addr netip.AddrPort) (Endpoint, error) {
	return c.parser.ParseEndpoint(addr.String())
}

func (c winRingUDPEndpointCodec) fromEndpoint(endpoint Endpoint) (netip.AddrPort, error) {
	switch ep := endpoint.(type) {
	case *windowsUDPEndpoint:
		return ep.addr, nil
	default:
		return netip.ParseAddrPort(endpoint.DstToString())
	}
}

func newDefaultWindowsUDPBind() Bind {
	fast := NewWinRingBind()
	fallback := NewStdNetBind()

	fastCodec := udpEndpointCodec(stdNetUDPEndpointCodec{})
	if _, ok := fast.(*WinRingBind); ok {
		fastCodec = winRingUDPEndpointCodec{parser: fast}
	}

	return newWindowsUDPBind(fast, fastCodec, fallback, stdNetUDPEndpointCodec{})
}

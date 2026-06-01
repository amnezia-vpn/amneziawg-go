package conn

import "github.com/amnezia-vpn/amneziawg-go/conceal"

type PreludeEndpoint interface {
	Endpoint
	PreludeState() *conceal.PreludeState
	ResetPreludeState()
}

type wrappedEndpoint interface {
	Endpoint
	UnwrapEndpoint() Endpoint
}

type preludeEndpoint struct {
	Endpoint
	prelude conceal.PreludeState
}

func wrapPreludeEndpoint(ep Endpoint) Endpoint {
	if ep == nil {
		return nil
	}
	if _, ok := ep.(PreludeEndpoint); ok {
		return ep
	}
	if _, ok := ep.(wrappedEndpoint); ok {
		return ep
	}
	return &preludeEndpoint{Endpoint: ep}
}

func unwrapEndpoint(ep Endpoint) Endpoint {
	for {
		wrapped, ok := ep.(wrappedEndpoint)
		if !ok {
			return ep
		}
		ep = wrapped.UnwrapEndpoint()
	}
}

func (e *preludeEndpoint) UnwrapEndpoint() Endpoint {
	return e.Endpoint
}

func (e *preludeEndpoint) ClearSrc() {
	e.Endpoint.ClearSrc()
	e.ResetPreludeState()
}

func (e *preludeEndpoint) PreludeState() *conceal.PreludeState {
	return &e.prelude
}

func (e *preludeEndpoint) ResetPreludeState() {
	e.prelude.Reset()
}

var _ PreludeEndpoint = (*preludeEndpoint)(nil)
var _ wrappedEndpoint = (*preludeEndpoint)(nil)

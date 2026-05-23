package conn

import "github.com/amnezia-vpn/amneziawg-go/conceal"

type PreludeEndpoint interface {
	Endpoint
	PreludeState() *conceal.PreludeState
	ResetPreludeState()
}

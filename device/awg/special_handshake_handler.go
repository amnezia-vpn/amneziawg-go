package awg

import (
	"github.com/tevino/abool"
	"go.uber.org/atomic"
)

// TODO: atomic?/ and better way to use this
var PacketCounter *atomic.Uint64 = atomic.NewUint64(0)

// TODO
var WaitResponse = struct {
	Channel    chan struct{}
	ShouldWait *abool.AtomicBool
}{
	make(chan struct{}, 1),
	abool.New(),
}

type SpecialHandshakeHandler struct {
	SpecialJunk TagJunkPacketGenerators

	IsSet bool
}

func (handler *SpecialHandshakeHandler) Validate() error {
	return handler.SpecialJunk.Validate()
}

func (handler *SpecialHandshakeHandler) GenerateSpecialJunk() [][]byte {
	if !handler.SpecialJunk.IsDefined() {
		return nil
	}

	return handler.SpecialJunk.GeneratePackets()
}

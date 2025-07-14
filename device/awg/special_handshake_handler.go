package awg

import (
	"errors"
	"time"

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
	isFirstDone    bool
	SpecialJunk    TagJunkPacketGenerators
	ControlledJunk TagJunkPacketGenerators

	nextItime time.Time
	ITimeout  time.Duration // seconds

	IsSet bool
}

func (handler *SpecialHandshakeHandler) Validate(maxSegmentSize int) error {
	var errs []error
	if err := handler.SpecialJunk.Validate(maxSegmentSize); err != nil {
		errs = append(errs, err)
	}
	if err := handler.ControlledJunk.Validate(maxSegmentSize); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (handler *SpecialHandshakeHandler) GenerateSpecialJunk() [][]byte {
	if !handler.SpecialJunk.IsDefined() {
		return nil
	}

	// TODO: create tests
	if !handler.isFirstDone {
		handler.isFirstDone = true
	} else if !handler.isTimeToSendSpecial() {
		return nil
	}

	rv := handler.SpecialJunk.GeneratePackets()
	handler.nextItime = time.Now().Add(handler.ITimeout)

	return rv
}

func (handler *SpecialHandshakeHandler) isTimeToSendSpecial() bool {
	return time.Now().After(handler.nextItime)
}

func (handler *SpecialHandshakeHandler) GenerateControlledJunk() [][]byte {
	if !handler.ControlledJunk.IsDefined() {
		return nil
	}

	return handler.ControlledJunk.GeneratePackets()
}

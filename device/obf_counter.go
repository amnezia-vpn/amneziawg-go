package device

import (
"encoding/binary"
"errors"
)

func newCounterObf(counterGetter func() uint32) (obf, error) {
	if counterGetter == nil {
		return nil, errors.New("counterGetter is required for <c> tag")
	}
	return &counterObf{
		counterGetter: counterGetter,
	}, nil
}

type counterObf struct {
	counterGetter func() uint32
}

func (o *counterObf) Obfuscate(dst, src []byte) {
	binary.BigEndian.PutUint32(dst, o.counterGetter())
}

func (o *counterObf) Deobfuscate(dst, src []byte) bool {
	// Counter value is not validated on receive side
	return true
}

func (o *counterObf) ObfuscatedLen(n int) int {
	return 4
}

func (o *counterObf) DeobfuscatedLen(n int) int {
	return 0
}

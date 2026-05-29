package device

import (
	"encoding/binary"
	"sync/atomic"
)

// packetCounter is a process-wide monotonic counter mixed into junk packets by
// the <c> tag. AmneziaWG 1.5 used a single shared counter (device/awg's
// PacketCounter); the exact value is never validated on receive (junk is
// discarded), it only needs to vary between packets.
var packetCounter atomic.Uint64

// newCounterObf builds the AmneziaWG 1.5 <c> tag: an 8-byte big-endian packet
// counter. It takes no parameter. Restored on top of the AWG 2.0 obf system for
// backward compatibility with 1.5 i1..i5 / j1..j3 specifications.
func newCounterObf(val string) (obf, error) {
	return &counterObf{}, nil
}

type counterObf struct{}

func (o *counterObf) Obfuscate(dst, src []byte) {
	binary.BigEndian.PutUint64(dst, packetCounter.Add(1))
}

func (o *counterObf) Deobfuscate(dst, src []byte) bool {
	// The counter carries no information that needs validating on receive.
	return true
}

func (o *counterObf) ObfuscatedLen(n int) int {
	return 8
}

func (o *counterObf) DeobfuscatedLen(n int) int {
	return 0
}

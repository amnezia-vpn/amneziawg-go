package device

import (
	"encoding/binary"
	"time"
)

func newTimestampObf(_ string) (obf, error) {
	return &timestampObf{}, nil
}

type timestampObf struct{}

func (o *timestampObf) Obfuscate(dst, src []byte) {
	t := uint32(time.Now().Unix())
	binary.BigEndian.PutUint32(dst, t)
}

func (o *timestampObf) Deobfuscate(dst, src []byte) bool {
	// replay attack check?
	// requires time to be always synchronized
	return true
}

func (o *timestampObf) ObfuscatedLen(n int) int {
	return 4
}

func (o *timestampObf) DeobfuscatedLen(n int) int {
	return 0
}

package device

import (
	"crypto/rand"
	"strconv"
)

func newRandObf(val string) (obf, error) {
	length, err := strconv.Atoi(val)
	if err != nil {
		return nil, err
	}

	return &randObf{
		length: length,
	}, nil
}

type randObf struct {
	length int
}

func (o *randObf) Obfuscate(dst, src []byte) {
	rand.Read(dst[:o.length])
}

func (o *randObf) Deobfuscate(dst, src []byte) bool {
	// there is no way to validate randomness :)
	// assume that it is always true
	return true
}

func (o *randObf) ObfuscatedLen(n int) int {
	return o.length
}

func (o *randObf) DeobfuscatedLen(n int) int {
	return 0
}

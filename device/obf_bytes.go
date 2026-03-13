package device

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
)

func newBytesObf(val string) (obf, error) {
	val = strings.TrimPrefix(val, "0x")

	if len(val) == 0 {
		return nil, errors.New("empty argument")
	}

	if len(val)%2 != 0 {
		return nil, errors.New("odd amount of symbols")
	}

	bytes, err := hex.DecodeString(val)
	if err != nil {
		return nil, err
	}

	return &bytesObf{data: bytes}, nil
}

type bytesObf struct {
	data []byte
}

func (o *bytesObf) Obfuscate(dst, src []byte) {
	copy(dst, o.data)
}

func (o *bytesObf) Deobfuscate(dst, src []byte) bool {
	return bytes.Equal(o.data, src[:o.ObfuscatedLen(0)])
}

func (o *bytesObf) ObfuscatedLen(srcLen int) int {
	return len(o.data)
}

func (o *bytesObf) DeobfuscatedLen(srcLen int) int {
	return 0
}

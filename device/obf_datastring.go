package device

import (
	"encoding/base64"
)

func newDataStringObf(val string) (obf, error) {
	return &dataStringObf{}, nil
}

type dataStringObf struct {
}

func (o *dataStringObf) Obfuscate(dst, src []byte) {
	base64.RawStdEncoding.Encode(dst, src)
}

func (o *dataStringObf) Deobfuscate(dst, src []byte) bool {
	base64.RawStdEncoding.Decode(dst, src)
	return true
}

func (o *dataStringObf) ObfuscatedLen(n int) int {
	return base64.RawStdEncoding.EncodedLen(n)
}

func (o *dataStringObf) DeobfuscatedLen(n int) int {
	return base64.RawStdEncoding.DecodedLen(n)
}

package device

func newDataObf(val string) (obf, error) {
	return &dataObf{}, nil
}

type dataObf struct {
}

func (obf *dataObf) Obfuscate(dst, src []byte) {
	copy(dst, src)
}

func (obf *dataObf) Deobfuscate(dst, src []byte) bool {
	copy(dst, src)
	return true
}

func (o *dataObf) ObfuscatedLen(n int) int {
	return n
}

func (o *dataObf) DeobfuscatedLen(n int) int {
	return n
}

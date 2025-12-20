package conceal

func NewFlexBuffer(buf []byte) *flexBuffer {
	return &flexBuffer{
		buf: buf,
	}
}

type flexBuffer struct {
	buf []byte
}

func (b *flexBuffer) TempBuffer(size int) []byte {
	if size > cap(b.buf)-len(b.buf) {
		return nil
	}
	return b.buf[len(b.buf) : len(b.buf)+size]
}

func (b *flexBuffer) PushTail(size int) []byte {
	oldLen := len(b.buf)
	newLen := oldLen + size
	if newLen > cap(b.buf) {
		return nil
	}

	b.buf = b.buf[:newLen]
	return b.buf[oldLen:]
}

func (b *flexBuffer) PullHead(size int) []byte {
	if size == -1 {
		size = len(b.buf)
	}

	if size > len(b.buf) {
		return nil
	}

	pulled := b.buf[:size]
	b.buf = b.buf[size:]
	return pulled
}

func (b *flexBuffer) Len() int {
	return len(b.buf)
}

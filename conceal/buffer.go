package conceal

import "sync"

func NewFlexBuffer(buf []byte) *flexBuffer {
	return &flexBuffer{
		buf: buf,
	}
}

type flexBuffer struct {
	buf    []byte
	offset int
	len    int
}

func (b *flexBuffer) PushTail(size int) []byte {
	newLen := b.len + size
	if b.offset+newLen > len(b.buf) {
		return nil
	}

	oldLen := b.len
	b.len = newLen
	return b.buf[b.offset+oldLen : b.offset+newLen]
}

func (b *flexBuffer) PullTail(size int) []byte {
	newLen := b.len - size
	if newLen < 0 {
		return nil
	}

	oldLen := b.len
	b.len = newLen
	return b.buf[b.offset+newLen : b.offset+oldLen]
}

func (b *flexBuffer) PullHead(size int) []byte {
	if size == -1 {
		size = len(b.buf)
	}

	newOffset := b.offset + size
	if newOffset+b.len > len(b.buf) {
		return nil
	}

	oldOffset := b.offset
	b.offset = newOffset

	return b.buf[oldOffset+b.len : newOffset+b.len]
}

func (b *flexBuffer) Cap() int {
	return len(b.buf)
}

func (b *flexBuffer) Len() int {
	return b.len
}

type BufferPool struct {
	sync.Pool
}

func (p *BufferPool) GetBuffer() []byte {
	return p.Get().([]byte)
}

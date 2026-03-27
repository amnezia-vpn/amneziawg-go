package conceal

import "sync"

func WrapFlexBuffer(buf []byte) FlexBuffer {
	return FlexBuffer{
		buf: buf,
	}
}

type FlexBuffer struct {
	buf    []byte
	offset int
	len    int
}

func (b *FlexBuffer) PushTail(size int) []byte {
	newLen := b.len + size
	if b.offset+newLen > len(b.buf) {
		return nil
	}

	oldLen := b.len
	b.len = newLen
	return b.buf[b.offset+oldLen : b.offset+newLen]
}

func (b *FlexBuffer) PullTail(size int) []byte {
	newLen := b.len - size
	if newLen < 0 {
		return nil
	}

	oldLen := b.len
	b.len = newLen
	return b.buf[b.offset+newLen : b.offset+oldLen]
}

func (b *FlexBuffer) PullHead(size int) []byte {
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

func (b *FlexBuffer) Cap() int {
	return len(b.buf)
}

func (b *FlexBuffer) Len() int {
	return b.len
}

func WrapBufferPool(pool *sync.Pool) *BufferPool {
	return &BufferPool{
		pool: pool,
	}
}

type BufferPool struct {
	pool *sync.Pool
}

func (p *BufferPool) Get() []byte {
	return p.pool.Get().([]byte)
}

func (p *BufferPool) Put(b []byte) {
	p.pool.Put(b)
}

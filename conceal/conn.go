package conceal

import (
	"net"
	"sync"
)

type ObfuscatedConn struct {
	net.Conn
	obfs Obfs
	bufs BufferPool
}

func NewObfuscatedConn(conn net.Conn, obfs Obfs) *ObfuscatedConn {
	return &ObfuscatedConn{
		Conn: conn,
		obfs: obfs,
		bufs: BufferPool{
			Pool: sync.Pool{
				New: func() any {
					// FIXME: put reasonable bufsize here
					return make([]byte, 2048)
				},
			},
		},
	}
}

func (c *ObfuscatedConn) Read(b []byte) (n int, err error) {
	ctx := &readContext{
		flexBuffer: NewFlexBuffer(b),
		tmpPool:    &c.bufs,
	}
	for _, obf := range c.obfs {
		if err := obf.Read(c.Conn, ctx); err != nil {
			return 0, err
		}
	}
	return ctx.Len(), nil
}

func (c *ObfuscatedConn) Write(b []byte) (n int, err error) {
	ctx := &writeContext{
		flexBuffer: NewFlexBuffer(b),
		tmpPool:    &c.bufs,
	}
	for _, obf := range c.obfs {
		if err := obf.Write(c.Conn, ctx); err != nil {
			return 0, err
		}
	}
	return ctx.Len(), nil
}

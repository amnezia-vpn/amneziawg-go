package conceal

import (
	"net"
)

type ObfuscatedConn struct {
	net.Conn
	obfs Obfs
}

func NewObfuscatedConn(conn net.Conn, obfs Obfs) *ObfuscatedConn {
	return &ObfuscatedConn{
		Conn: conn,
		obfs: obfs,
	}
}

func (c *ObfuscatedConn) Read(b []byte) (n int, err error) {
	ctx := &readContext{
		flexBuffer: NewFlexBuffer(b[:0]),
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
	}
	for _, obf := range c.obfs {
		if err := obf.Write(c.Conn, ctx); err != nil {
			return 0, err
		}
	}
	return ctx.Len(), nil
}

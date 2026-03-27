package conceal

import (
	"net"
	"sync"

	"golang.org/x/net/ipv4"
)

type MasqueradeOpts struct {
	RulesIn  Rules
	RulesOut Rules
}

func NewMasqueradeConn(conn net.Conn, pool *sync.Pool, opts MasqueradeOpts) (c *MasqueradeConn, ok bool) {
	if opts.RulesIn == nil && opts.RulesOut == nil {
		return nil, false
	}

	return &MasqueradeConn{
		Conn:     conn,
		rulesIn:  opts.RulesIn,
		rulesOut: opts.RulesOut,
		pool:     WrapBufferPool(pool),
	}, true
}

type MasqueradeConn struct {
	net.Conn
	rulesIn  Rules
	rulesOut Rules
	pool     *BufferPool
}

var _ StreamRecordConn = (*MasqueradeConn)(nil)

func (c *MasqueradeConn) CanReadRecord() bool {
	return c.rulesIn != nil
}

func (c *MasqueradeConn) CanWriteRecord() bool {
	return c.rulesOut != nil
}

func (c *MasqueradeConn) ReadRecord(b []byte) (n int, err error) {
	if !c.CanReadRecord() {
		return 0, ErrNoReadRecord
	}

	ctx := readContext{
		FlexBuffer: WrapFlexBuffer(b),
		BufferPool: c.pool,
	}

	if err := c.rulesIn.Read(c.Conn, &ctx); err != nil {
		return 0, err
	}

	return ctx.Len(), nil
}

func (c *MasqueradeConn) WriteRecord(b []byte) (n int, err error) {
	if !c.CanWriteRecord() {
		return 0, ErrNoWriteRecord
	}

	ctx := writeContext{
		FlexBuffer: WrapFlexBuffer(b),
		BufferPool: c.pool,
	}

	t := c.pool.Get()
	w := newSliceWriter(t)

	if err := c.rulesOut.Write(&w, &ctx); err != nil {
		c.pool.Put(t)
		return 0, err
	}

	if _, err := c.Conn.Write(w.Bytes()); err != nil {
		c.pool.Put(t)
		return 0, err
	}

	c.pool.Put(t)
	return len(b), nil
}

func (c *MasqueradeConn) Read(b []byte) (n int, err error) {
	if !c.CanReadRecord() {
		return c.Conn.Read(b)
	}
	return c.ReadRecord(b)
}

func (c *MasqueradeConn) Write(b []byte) (n int, err error) {
	if !c.CanWriteRecord() {
		return c.Conn.Write(b)
	}
	return c.WriteRecord(b)
}

func NewMasqueradeUDPConn(conn UDPConn, pool *sync.Pool, opts MasqueradeOpts) (c *MasqueradeUDPConn, ok bool) {
	if opts.RulesIn == nil && opts.RulesOut == nil {
		return nil, false
	}

	return &MasqueradeUDPConn{
		UDPConn:  conn,
		rulesIn:  opts.RulesIn,
		rulesOut: opts.RulesOut,
		pool:     WrapBufferPool(pool),
	}, true
}

type MasqueradeUDPConn struct {
	UDPConn
	rulesIn  Rules
	rulesOut Rules
	pool     *BufferPool
}

func (c *MasqueradeUDPConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	n, oobn, flags, addr, err = c.UDPConn.ReadMsgUDP(b, oob)
	if err != nil {
		return n, oobn, flags, addr, err
	}

	r := newSliceReader(b[:n])
	ctx := readContext{
		FlexBuffer: WrapFlexBuffer(b),
		BufferPool: c.pool,
	}

	if err = c.rulesIn.Read(&r, &ctx); err != nil {
		return 0, oobn, flags, addr, err
	}

	return ctx.Len(), oobn, flags, addr, err
}

func (c *MasqueradeUDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	t := c.pool.Get()
	w := newSliceWriter(t)
	ctx := writeContext{
		FlexBuffer: WrapFlexBuffer(b),
		BufferPool: c.pool,
	}

	if err = c.rulesOut.Write(&w, &ctx); err != nil {
		c.pool.Put(t)
		return 0, 0, err
	}

	n, oobn, err = c.UDPConn.WriteMsgUDP(w.Bytes(), oob, addr)
	c.pool.Put(t)
	if err != nil {
		return 0, oobn, err
	}
	return len(b), oobn, nil
}

func NewMasqueradeBatchConn(conn BatchConn, bp *sync.Pool, opts MasqueradeOpts) (c *MasqueradeBatchConn, ok bool) {
	if opts.RulesIn == nil && opts.RulesOut == nil {
		return nil, false
	}

	return &MasqueradeBatchConn{
		BatchConn: conn,
		rulesIn:   opts.RulesIn,
		rulesOut:  opts.RulesOut,
		pool:      WrapBufferPool(bp),
	}, true
}

type MasqueradeBatchConn struct {
	BatchConn
	rulesIn  Rules
	rulesOut Rules
	pool     *BufferPool
}

func (c *MasqueradeBatchConn) ReadBatch(ms []ipv4.Message, flags int) (n int, err error) {
	n, err = c.BatchConn.ReadBatch(ms, flags)
	if err != nil {
		return 0, err
	}

	for i := range n {
		r := newSliceReader(ms[i].Buffers[0][:ms[i].N])
		ctx := readContext{
			FlexBuffer: WrapFlexBuffer(ms[i].Buffers[0]),
			BufferPool: c.pool,
		}

		if err = c.rulesIn.Read(&r, &ctx); err != nil {
			return 0, err
		}

		ms[i].N = ctx.Len()
	}

	return n, nil
}

func (c *MasqueradeBatchConn) WriteBatch(ms []ipv4.Message, flags int) (n int, err error) {
	var inline [128][]byte
	pooled := inline[:0]
	if len(ms) > len(inline) {
		pooled = make([][]byte, 0, len(ms))
	}

	for i := range ms {
		t := c.pool.Get()
		pooled = append(pooled, t)

		w := newSliceWriter(t)
		ctx := writeContext{
			FlexBuffer: WrapFlexBuffer(ms[i].Buffers[0]),
			BufferPool: c.pool,
		}

		if err = c.rulesOut.Write(&w, &ctx); err != nil {
			for _, buf := range pooled {
				c.pool.Put(buf)
			}
			return 0, err
		}

		ms[i].Buffers[0] = w.Bytes()
	}

	n, err = c.BatchConn.WriteBatch(ms, flags)
	for _, buf := range pooled {
		c.pool.Put(buf)
	}
	return n, err
}

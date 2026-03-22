package conceal

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"net"
	"sync"

	"golang.org/x/net/ipv4"
)

type PreludeOpts struct {
	Jc       int
	Jmin     int
	Jmax     int
	RulesArr [5]Rules
}

func (o PreludeOpts) IsEmpty() bool {
	for _, rules := range o.RulesArr {
		if rules != nil {
			return false
		}
	}
	return o.Jc == 0
}

func newJunkGenerator(min, max int) *junkGenerator {
	return &junkGenerator{
		rang:   big.NewInt(int64(max - min + 1)),
		offset: min,
	}
}

type junkGenerator struct {
	rang   *big.Int
	offset int
}

func (p *junkGenerator) generate(b []byte) []byte {
	rndBig, _ := rand.Int(rand.Reader, p.rang)
	n := int(rndBig.Int64()) + p.offset

	junk := b[:n]
	rand.Read(junk)
	return junk
}

func NewPreludeUDPConn(
	conn UDPConn,
	origin UDPConn,
	pool *sync.Pool,
	header *RangedHeader,
	opts PreludeOpts,
) (c *PreludeUDPConn, ok bool) {
	if opts.IsEmpty() {
		return nil, false
	}

	if opts.Jmin > opts.Jmax {
		opts.Jmin, opts.Jmax = opts.Jmax, opts.Jmin
	}

	return &PreludeUDPConn{
		UDPConn:   conn,
		origin:    origin,
		pool:      WrapBufferPool(pool),
		rulesArr:  opts.RulesArr,
		junkCount: opts.Jc,
		junkGen:   newJunkGenerator(opts.Jmin, opts.Jmax),
		header:    header,
	}, true
}

type PreludeUDPConn struct {
	UDPConn
	origin    UDPConn
	pool      *BufferPool
	rulesArr  [5]Rules
	junkCount int
	junkGen   *junkGenerator
	header    *RangedHeader
}

func (c *PreludeUDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	var isInit bool
	if len(b) >= 4 {
		typ := binary.LittleEndian.Uint32(b[:4])
		if c.header != nil {
			isInit = c.header.Validate(typ)
		} else {
			isInit = typ == WireguardMsgInitiationType
		}
	}

	if isInit {
		b := c.pool.Get()
		defer c.pool.Put(b)

		ctx := &writeContext{
			FlexBuffer: WrapFlexBuffer(nil),
			BufferPool: c.pool,
		}

		for _, rules := range c.rulesArr {
			if rules == nil {
				continue
			}

			w := bytes.NewBuffer(b[:0])
			if err = rules.Write(w, ctx); err != nil {
				return 0, 0, err
			}

			if _, _, err = c.origin.WriteMsgUDP(w.Bytes(), oob, addr); err != nil {
				return 0, 0, err
			}
		}

		for range c.junkCount {
			junk := c.junkGen.generate(b)
			if _, _, err = c.origin.WriteMsgUDP(junk, oob, addr); err != nil {
				return 0, 0, err
			}
		}
	}

	return c.UDPConn.WriteMsgUDP(b, oob, addr)
}

func newStreamPreludeHeader(opts FramedOpts) *RangedHeader {
	if opts.H1 != nil {
		return opts.H1
	}
	return &RangedHeader{
		start: WireguardMsgInitiationType,
		end:   WireguardMsgInitiationType,
	}
}

func NewPreludeConn(
	conn net.Conn,
	pool *sync.Pool,
	framedOpts FramedOpts,
	opts PreludeOpts,
) (c *PreludeConn, ok bool) {
	if opts.IsEmpty() {
		return nil, false
	}

	if opts.Jmin > opts.Jmax {
		opts.Jmin, opts.Jmax = opts.Jmax, opts.Jmin
	}

	return &PreludeConn{
		Conn:      conn,
		pool:      WrapBufferPool(pool),
		rulesArr:  opts.RulesArr,
		junkCount: opts.Jc,
		junkGen:   newJunkGenerator(opts.Jmin, opts.Jmax),
		header:    newStreamPreludeHeader(framedOpts),
	}, true
}

type PreludeConn struct {
	net.Conn
	pool      *BufferPool
	rulesArr  [5]Rules
	junkCount int
	junkGen   *junkGenerator
	header    *RangedHeader
}

func (c *PreludeConn) Write(b []byte) (n int, err error) {
	var isInit bool
	if len(b) >= 4 {
		isInit = c.header.Validate(binary.LittleEndian.Uint32(b[:4]))
	}

	if isInit {
		buf := c.pool.Get()
		defer c.pool.Put(buf)

		ctx := &writeContext{
			FlexBuffer: WrapFlexBuffer(nil),
			BufferPool: c.pool,
		}

		for _, rules := range c.rulesArr {
			if rules == nil {
				continue
			}

			w := bytes.NewBuffer(buf[:0])
			if err = rules.Write(w, ctx); err != nil {
				return 0, err
			}

			if _, err = c.Conn.Write(w.Bytes()); err != nil {
				return 0, err
			}
		}

		for range c.junkCount {
			if _, err = c.Conn.Write(c.junkGen.generate(buf)); err != nil {
				return 0, err
			}
		}
	}

	return c.Conn.Write(b)
}

func NewPreludeBatchConn(
	conn BatchConn,
	origin BatchConn,
	bufPool *sync.Pool,
	msgsPool *sync.Pool,
	header *RangedHeader,
	opts PreludeOpts,
) (c *PreludeBatchConn, ok bool) {
	if opts.IsEmpty() {
		return nil, false
	}

	if opts.Jmin > opts.Jmax {
		opts.Jmin, opts.Jmax = opts.Jmax, opts.Jmin
	}

	return &PreludeBatchConn{
		BatchConn: conn,
		origin:    origin,
		bufPool:   WrapBufferPool(bufPool),
		msgsPool:  msgsPool,
		rulesArr:  opts.RulesArr,
		junkCount: opts.Jc,
		junkGen:   newJunkGenerator(opts.Jmin, opts.Jmax),
		header:    header,
	}, true
}

type PreludeBatchConn struct {
	BatchConn
	origin    BatchConn
	bufPool   *BufferPool
	msgsPool  *sync.Pool
	rulesArr  [5]Rules
	junkCount int
	junkGen   *junkGenerator
	header    *RangedHeader
}

func (c *PreludeBatchConn) WriteBatch(ms []ipv4.Message, flags int) (n int, err error) {
	var initMsg *ipv4.Message
	for i := range ms {
		b := ms[i].Buffers[0]

		var isInit bool
		if len(b) >= 4 {
			typ := binary.LittleEndian.Uint32(b[:4])
			if c.header != nil {
				isInit = c.header.Validate(typ)
			} else {
				isInit = typ == WireguardMsgInitiationType
			}
		}
		if isInit {
			initMsg = &ms[i]
		}
	}

	if initMsg != nil {
		ctx := &writeContext{
			FlexBuffer: WrapFlexBuffer(nil),
			BufferPool: c.bufPool,
		}

		msgs := c.msgsPool.Get().(*[]ipv4.Message)
		defer c.msgsPool.Put(msgs)
		i := 0

		for _, rules := range c.rulesArr {
			if rules == nil {
				continue
			}

			buf := c.bufPool.Get()
			defer c.bufPool.Put(buf)

			w := bytes.NewBuffer(buf[:0])
			if err = rules.Write(w, ctx); err != nil {
				return 0, err
			}

			(*msgs)[i].Buffers[0] = w.Bytes()
			(*msgs)[i].OOB = initMsg.OOB
			(*msgs)[i].Addr = initMsg.Addr
			i++
		}

		for range c.junkCount {
			buf := c.bufPool.Get()
			defer c.bufPool.Put(buf)

			(*msgs)[i].Buffers[0] = c.junkGen.generate(buf)
			(*msgs)[i].OOB = initMsg.OOB
			(*msgs)[i].Addr = initMsg.Addr
			i++
		}

		var start int
		for {
			m := (*msgs)[start:i]
			n, err = c.origin.WriteBatch(m, flags)
			if err != nil {
				return 0, err
			}
			if n == len(m) {
				break
			}
			start += n
		}
	}

	return c.BatchConn.WriteBatch(ms, flags)
}

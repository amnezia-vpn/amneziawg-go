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

func NewPreludeConn(
	conn StreamRecordConn,
	pool *sync.Pool,
	framedOpts FramedOpts,
	opts PreludeOpts,
) (c *PreludeConn, ok bool) {
	if opts.IsEmpty() || !conn.CanReadRecord() || !conn.CanWriteRecord() {
		return nil, false
	}

	if opts.Jmin > opts.Jmax {
		opts.Jmin, opts.Jmax = opts.Jmax, opts.Jmin
	}

	enc, _ := newFrameEncoding(framedOpts)

	return &PreludeConn{
		StreamRecordConn: conn,
		pool:             WrapBufferPool(pool),
		rulesArr:         opts.RulesArr,
		junkCount:        opts.Jc,
		junkGen:          newJunkGenerator(opts.Jmin, opts.Jmax),
		recordEncoding:   enc,
	}, true
}

type PreludeConn struct {
	StreamRecordConn
	pool           *BufferPool
	rulesArr       [5]Rules
	junkCount      int
	junkGen        *junkGenerator
	recordEncoding frameEncoding
	seenValid      bool
}

func (c *PreludeConn) Read(b []byte) (n int, err error) {
	if c.seenValid {
		return c.StreamRecordConn.ReadRecord(b)
	}

	for {
		n, err = c.StreamRecordConn.ReadRecord(b)
		if err != nil {
			return 0, err
		}
		if c.recordEncoding.IsValidRecord(b[:n]) {
			c.seenValid = true
			return n, nil
		}
	}
}

func (c *PreludeConn) Write(b []byte) (n int, err error) {
	if c.recordEncoding.IsInitiationRecord(b) {
		if err := c.writePreludeRecords(); err != nil {
			return 0, err
		}
	}

	return c.StreamRecordConn.WriteRecord(b)
}

func (c *PreludeConn) writePreludeRecords() (err error) {
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
			return err
		}

		if _, err = c.StreamRecordConn.WriteRecord(w.Bytes()); err != nil {
			return err
		}
	}

	for range c.junkCount {
		if _, err = c.StreamRecordConn.WriteRecord(c.junkGen.generate(buf)); err != nil {
			return err
		}
	}

	return nil
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

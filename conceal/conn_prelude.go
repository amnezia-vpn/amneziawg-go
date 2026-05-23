package conceal

import (
	"crypto/rand"
	"math/big"
	"net"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
)

const DefaultPreludeResendInterval = 120 * time.Second

type PreludeOpts struct {
	Jc             int
	Jmin           int
	Jmax           int
	ResendInterval time.Duration
	RulesArr       [5]Rules
}

type PreludeState struct {
	mu       sync.Mutex
	sent     bool
	lastSent time.Time
}

func (s *PreludeState) ClaimSend(now time.Time, resendInterval time.Duration) bool {
	if s == nil {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.sent {
		s.sent = true
		s.lastSent = now
		return true
	}

	if resendInterval <= 0 || now.Sub(s.lastSent) < resendInterval {
		return false
	}

	s.lastSent = now
	return true
}

func (s *PreludeState) Reset() {
	if s == nil {
		return
	}

	s.mu.Lock()
	s.sent = false
	s.lastSent = time.Time{}
	s.mu.Unlock()
}

func (o PreludeOpts) HasDecoyRules() bool {
	for _, rules := range o.RulesArr {
		if rules != nil {
			return true
		}
	}
	return false
}

func (o PreludeOpts) IsEmpty() bool {
	if o.HasDecoyRules() {
		return false
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
	_ *RangedHeader,
	opts PreludeOpts,
) (c *PreludeUDPConn, ok bool) {
	if opts.IsEmpty() {
		return nil, false
	}

	if opts.Jmin > opts.Jmax {
		opts.Jmin, opts.Jmax = opts.Jmax, opts.Jmin
	}

	return &PreludeUDPConn{
		UDPConn:        conn,
		origin:         origin,
		pool:           WrapBufferPool(pool),
		rulesArr:       opts.RulesArr,
		junkCount:      opts.Jc,
		junkGen:        newJunkGenerator(opts.Jmin, opts.Jmax),
		resendInterval: opts.ResendInterval,
	}, true
}

type PreludeUDPConn struct {
	UDPConn
	origin         UDPConn
	pool           *BufferPool
	rulesArr       [5]Rules
	junkCount      int
	junkGen        *junkGenerator
	statesMu       sync.Mutex
	states         map[string]*PreludeState
	resendInterval time.Duration
}

func (c *PreludeUDPConn) preludeState(addr net.Addr) *PreludeState {
	key := ""
	if addr != nil {
		key = addr.String()
	}

	c.statesMu.Lock()
	defer c.statesMu.Unlock()
	if c.states == nil {
		c.states = make(map[string]*PreludeState)
	}
	state := c.states[key]
	if state == nil {
		state = new(PreludeState)
		c.states[key] = state
	}
	return state
}

func (c *PreludeUDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	state := c.preludeState(addr)
	if state.ClaimSend(time.Now(), c.resendInterval) {
		buf := c.pool.Get()
		ctx := writeContext{
			FlexBuffer: WrapFlexBuffer(nil),
			BufferPool: c.pool,
		}
		w := newSliceWriter(buf)

		for _, rules := range c.rulesArr {
			if rules == nil {
				continue
			}

			w.Reset(buf)
			if err = rules.Write(&w, &ctx); err != nil {
				c.pool.Put(buf)
				state.Reset()
				return 0, 0, err
			}

			if _, _, err = c.origin.WriteMsgUDP(w.Bytes(), oob, addr); err != nil {
				c.pool.Put(buf)
				state.Reset()
				return 0, 0, err
			}
		}

		for range c.junkCount {
			junk := c.junkGen.generate(buf)
			if _, _, err = c.origin.WriteMsgUDP(junk, oob, addr); err != nil {
				c.pool.Put(buf)
				state.Reset()
				return 0, 0, err
			}
		}

		c.pool.Put(buf)
	}

	return c.UDPConn.WriteMsgUDP(b, oob, addr)
}

func NewPreludeConn(
	conn StreamRecordConn,
	pool *sync.Pool,
	framedOpts FramedOpts,
	opts PreludeOpts,
) (c *PreludeConn, ok bool) {
	return NewPreludeConnWithState(conn, pool, framedOpts, opts, nil, false)
}

func NewPreludeConnWithState(
	conn StreamRecordConn,
	pool *sync.Pool,
	framedOpts FramedOpts,
	opts PreludeOpts,
	state *PreludeState,
	emitOutbound bool,
) (c *PreludeConn, ok bool) {
	if !opts.HasDecoyRules() || !conn.CanReadRecord() || !conn.CanWriteRecord() {
		return nil, false
	}

	enc, _ := newFrameEncoding(framedOpts)

	return &PreludeConn{
		StreamRecordConn: conn,
		pool:             WrapBufferPool(pool),
		rulesArr:         opts.RulesArr,
		resendInterval:   opts.ResendInterval,
		state:            state,
		emitOutbound:     emitOutbound,
		recordEncoding:   enc,
	}, true
}

type PreludeConn struct {
	StreamRecordConn
	pool           *BufferPool
	rulesArr       [5]Rules
	resendInterval time.Duration
	state          *PreludeState
	emitOutbound   bool
	recordEncoding frameEncoding
	seenValid      bool
}

func (c *PreludeConn) Read(b []byte) (n int, err error) {
	for {
		n, err = c.StreamRecordConn.ReadRecord(b)
		if err != nil {
			return 0, err
		}
		if c.recordEncoding.IsValidRecord(b[:n]) {
			c.seenValid = true
			return n, nil
		}
		if c.isPreludeRecord(b[:n]) {
			continue
		}
		return 0, NewFormatError(b[:n], errInvalidData)
	}
}

func (c *PreludeConn) isPreludeRecord(b []byte) bool {
	for _, rules := range c.rulesArr {
		if rules.Match(b, c.pool) {
			return true
		}
	}
	return false
}

func (c *PreludeConn) Write(b []byte) (n int, err error) {
	if c.emitOutbound && c.state != nil && c.state.ClaimSend(time.Now(), c.resendInterval) {
		if err := c.writePreludeRecords(); err != nil {
			c.state.Reset()
			return 0, err
		}
	}

	return c.StreamRecordConn.WriteRecord(b)
}

func (c *PreludeConn) writePreludeRecords() (err error) {
	buf := c.pool.Get()
	ctx := writeContext{
		FlexBuffer: WrapFlexBuffer(nil),
		BufferPool: c.pool,
	}
	w := newSliceWriter(buf)

	for _, rules := range c.rulesArr {
		if rules == nil {
			continue
		}

		w.Reset(buf)
		if err = rules.Write(&w, &ctx); err != nil {
			c.pool.Put(buf)
			return err
		}

		if _, err = c.StreamRecordConn.WriteRecord(w.Bytes()); err != nil {
			c.pool.Put(buf)
			return err
		}
	}

	c.pool.Put(buf)
	return nil
}

func NewPreludeBatchConn(
	conn BatchConn,
	origin BatchConn,
	bufPool *sync.Pool,
	msgsPool *sync.Pool,
	_ *RangedHeader,
	opts PreludeOpts,
) (c *PreludeBatchConn, ok bool) {
	if opts.IsEmpty() {
		return nil, false
	}

	if opts.Jmin > opts.Jmax {
		opts.Jmin, opts.Jmax = opts.Jmax, opts.Jmin
	}

	return &PreludeBatchConn{
		BatchConn:      conn,
		origin:         origin,
		bufPool:        WrapBufferPool(bufPool),
		msgsPool:       msgsPool,
		rulesArr:       opts.RulesArr,
		junkCount:      opts.Jc,
		junkGen:        newJunkGenerator(opts.Jmin, opts.Jmax),
		resendInterval: opts.ResendInterval,
	}, true
}

type PreludeBatchConn struct {
	BatchConn
	origin         BatchConn
	bufPool        *BufferPool
	msgsPool       *sync.Pool
	rulesArr       [5]Rules
	junkCount      int
	junkGen        *junkGenerator
	statesMu       sync.Mutex
	states         map[string]*PreludeState
	resendInterval time.Duration
}

func (c *PreludeBatchConn) preludeState(addr net.Addr) *PreludeState {
	key := ""
	if addr != nil {
		key = addr.String()
	}

	c.statesMu.Lock()
	defer c.statesMu.Unlock()
	if c.states == nil {
		c.states = make(map[string]*PreludeState)
	}
	state := c.states[key]
	if state == nil {
		state = new(PreludeState)
		c.states[key] = state
	}
	return state
}

func (c *PreludeBatchConn) WriteBatch(ms []ipv4.Message, flags int) (n int, err error) {
	if len(ms) == 0 {
		return c.BatchConn.WriteBatch(ms, flags)
	}

	preludeMsg := &ms[0]
	state := c.preludeState(preludeMsg.Addr)
	if state.ClaimSend(time.Now(), c.resendInterval) {
		ctx := writeContext{
			FlexBuffer: WrapFlexBuffer(nil),
			BufferPool: c.bufPool,
		}

		msgs := c.msgsPool.Get().(*[]ipv4.Message)
		count := c.junkCount
		for _, rules := range c.rulesArr {
			if rules != nil {
				count++
			}
		}

		var inline [32][]byte
		pooled := inline[:0]
		if count > len(inline) {
			pooled = make([][]byte, 0, count)
		}

		i := 0

		for _, rules := range c.rulesArr {
			if rules == nil {
				continue
			}

			buf := c.bufPool.Get()
			pooled = append(pooled, buf)

			w := newSliceWriter(buf)
			if err = rules.Write(&w, &ctx); err != nil {
				for _, pooledBuf := range pooled {
					c.bufPool.Put(pooledBuf)
				}
				c.msgsPool.Put(msgs)
				state.Reset()
				return 0, err
			}

			(*msgs)[i].Buffers[0] = w.Bytes()
			(*msgs)[i].OOB = preludeMsg.OOB
			(*msgs)[i].Addr = preludeMsg.Addr
			i++
		}

		for range c.junkCount {
			buf := c.bufPool.Get()
			pooled = append(pooled, buf)

			(*msgs)[i].Buffers[0] = c.junkGen.generate(buf)
			(*msgs)[i].OOB = preludeMsg.OOB
			(*msgs)[i].Addr = preludeMsg.Addr
			i++
		}

		var start int
		for {
			m := (*msgs)[start:i]
			n, err = c.origin.WriteBatch(m, flags)
			if err != nil {
				for _, pooledBuf := range pooled {
					c.bufPool.Put(pooledBuf)
				}
				c.msgsPool.Put(msgs)
				state.Reset()
				return 0, err
			}
			if n == len(m) {
				break
			}
			start += n
		}

		for _, pooledBuf := range pooled {
			c.bufPool.Put(pooledBuf)
		}
		c.msgsPool.Put(msgs)
	}

	return c.BatchConn.WriteBatch(ms, flags)
}

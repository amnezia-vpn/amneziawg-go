package conn

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conceal"
)

var (
	_ Bind          = (*ConcealBind)(nil)
	_ Framable      = (*ConcealBind)(nil)
	_ Preludable    = (*ConcealBind)(nil)
	_ Masqueradable = (*ConcealBind)(nil)
	_ Fallbackable  = (*ConcealBind)(nil)
)

type ConcealBind struct {
	inner Bind

	mu sync.Mutex

	bufPool sync.Pool

	framedOpts     conceal.FramedOpts
	preludeOpts    conceal.PreludeOpts
	masqueradeOpts conceal.MasqueradeOpts
	fallbackPort   uint16

	fallbackSessions map[string]*concealBindFallbackSession
	preludeStates    map[string]*conceal.PreludeState

	pipeline atomic.Pointer[conceal.UDPDatagramPipeline]
}

func NewConcealBind(inner Bind) *ConcealBind {
	bind := &ConcealBind{
		inner: inner,
		bufPool: sync.Pool{
			New: func() any {
				return make([]byte, 65535)
			},
		},
	}
	bind.rebuildPipelineLocked()
	return bind
}

func (b *ConcealBind) rebuildPipelineLocked() {
	b.pipeline.Store(conceal.NewUDPDatagramPipeline(&b.bufPool, b.framedOpts, b.preludeOpts, b.masqueradeOpts))
}

func (b *ConcealBind) currentPipeline() *conceal.UDPDatagramPipeline {
	return b.pipeline.Load()
}

func (b *ConcealBind) udpConcealPipeline() concealPipeline {
	b.mu.Lock()
	defer b.mu.Unlock()
	return udpConcealPipeline(b.framedOpts, b.preludeOpts, b.masqueradeOpts)
}

func (b *ConcealBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	recvFns, actualPort, err := b.inner.Open(port)
	if err != nil {
		return nil, 0, err
	}

	wrapped := make([]ReceiveFunc, len(recvFns))
	for i, fn := range recvFns {
		wrapped[i] = b.wrapReceiveFunc(fn)
	}

	return wrapped, actualPort, nil
}

func (b *ConcealBind) wrapReceiveFunc(fn ReceiveFunc) ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []Endpoint) (int, error) {
		n, err := fn(packets, sizes, eps)
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, nil
		}

		pipeline := b.currentPipeline()
		if pipeline == nil || !pipeline.Active() {
			return n, nil
		}

		for i := 0; i < n; i++ {
			if sizes[i] == 0 || eps[i] == nil {
				sizes[i] = 0
				eps[i] = nil
				continue
			}

			size, err := pipeline.DecodeInPlaceErr(packets[i], sizes[i])
			if err != nil {
				if errors.Is(err, conceal.ErrFormat) {
					data := conceal.FormatErrorData(err)
					if len(data) == 0 {
						data = bytes.Clone(packets[i][:sizes[i]])
					}
					_ = b.forwardFallbackUDP(eps[i], data)
				}
				sizes[i] = 0
				eps[i] = nil
				continue
			}

			sizes[i] = size
		}
		return n, nil
	}
}

func (b *ConcealBind) Close() error {
	b.mu.Lock()
	b.closeFallbackSessionsLocked()
	b.mu.Unlock()
	return b.inner.Close()
}

func (b *ConcealBind) SetMark(mark uint32) error {
	return b.inner.SetMark(mark)
}

func (b *ConcealBind) preludeState(ep Endpoint) *conceal.PreludeState {
	if ep == nil {
		return nil
	}
	if preludeEP, ok := ep.(PreludeEndpoint); ok {
		return preludeEP.PreludeState()
	}

	key := ep.DstToString()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.preludeStates == nil {
		b.preludeStates = make(map[string]*conceal.PreludeState)
	}
	state := b.preludeStates[key]
	if state == nil {
		state = new(conceal.PreludeState)
		b.preludeStates[key] = state
	}
	return state
}

func (b *ConcealBind) resetPreludeState(ep Endpoint) {
	if ep == nil {
		return
	}
	if preludeEP, ok := ep.(PreludeEndpoint); ok {
		preludeEP.ResetPreludeState()
		return
	}

	key := ep.DstToString()
	b.mu.Lock()
	if state := b.preludeStates[key]; state != nil {
		state.Reset()
	}
	b.mu.Unlock()
}

func (b *ConcealBind) Send(bufs [][]byte, ep Endpoint) error {
	if len(bufs) == 0 {
		return nil
	}

	pipeline := b.currentPipeline()
	if pipeline == nil || !pipeline.Active() {
		return b.inner.Send(bufs, ep)
	}

	batchSize := b.inner.BatchSize()
	if batchSize < 1 {
		batchSize = 1
	}

	batch := make([][]byte, 0, batchSize)
	retained := make([][]byte, 0, batchSize)

	putRetained := func() {
		for i, buf := range retained {
			b.bufPool.Put(buf)
			retained[i] = nil
		}
		retained = retained[:0]
	}
	clearBatch := func() {
		for i := range batch {
			batch[i] = nil
		}
		batch = batch[:0]
	}
	defer func() {
		putRetained()
		clearBatch()
	}()

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := b.inner.Send(batch, ep)
		putRetained()
		clearBatch()
		return err
	}

	appendPacket := func(packet []byte, retainedBuf []byte) error {
		if len(batch) == batchSize {
			if err := flush(); err != nil {
				if retainedBuf != nil {
					b.bufPool.Put(retainedBuf)
				}
				return err
			}
		}

		batch = append(batch, packet)
		if retainedBuf != nil {
			retained = append(retained, retainedBuf)
		}

		if len(batch) == batchSize {
			return flush()
		}
		return nil
	}

	preludeState := b.preludeState(ep)
	if pipeline.PreludeActive() && preludeState != nil && preludeState.ClaimSend(time.Now(), pipeline.PreludeResendInterval()) {
		if err := pipeline.EmitPrelude(func(packet []byte) error {
			return appendPacket(bytes.Clone(packet), nil)
		}); err != nil {
			b.resetPreludeState(ep)
			return err
		}
	}

	for _, buf := range bufs {
		encoded := b.bufPool.Get().([]byte)
		n, err := pipeline.Encode(encoded, buf)
		if err != nil {
			b.bufPool.Put(encoded)
			return err
		}
		if err := appendPacket(encoded[:n], encoded); err != nil {
			return err
		}
	}

	return flush()
}

func (b *ConcealBind) ParseEndpoint(s string) (Endpoint, error) {
	ep, err := b.inner.ParseEndpoint(s)
	if err != nil {
		return nil, err
	}
	b.resetPreludeState(ep)
	return ep, nil
}

func (b *ConcealBind) BatchSize() int {
	return b.inner.BatchSize()
}

func (b *ConcealBind) SetFramedOpts(opts conceal.FramedOpts) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.framedOpts = opts
	b.rebuildPipelineLocked()
}

func (b *ConcealBind) SetPreludeOpts(opts conceal.PreludeOpts) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.preludeOpts = opts
	b.rebuildPipelineLocked()
}

func (b *ConcealBind) SetMasqueradeOpts(opts conceal.MasqueradeOpts) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.masqueradeOpts = opts
	b.rebuildPipelineLocked()
}

func (b *ConcealBind) SetFallbackPort(port uint16) {
	b.mu.Lock()
	if b.fallbackPort != port {
		b.closeFallbackSessionsLocked()
	}
	b.fallbackPort = port
	b.mu.Unlock()

	if fallbackable, ok := b.inner.(Fallbackable); ok {
		fallbackable.SetFallbackPort(port)
	}
}

func (b *ConcealBind) forwardFallbackUDP(ep Endpoint, data []byte) error {
	if ep == nil || len(data) == 0 {
		return nil
	}

	port := b.currentFallbackPort()
	if port == 0 {
		return nil
	}

	session, err := b.fallbackSession(ep, port)
	if err != nil {
		return err
	}
	_, err = session.conn.Write(data)
	return err
}

func (b *ConcealBind) currentFallbackPort() uint16 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.fallbackPort
}

func (b *ConcealBind) fallbackSession(ep Endpoint, port uint16) (*concealBindFallbackSession, error) {
	key := ep.DstToString()

	b.mu.Lock()
	if session := b.fallbackSessions[key]; session != nil {
		b.mu.Unlock()
		return session, nil
	}
	b.mu.Unlock()

	fallbackConn, err := net.DialUDP("udp", nil, fallbackUDPAddressForEndpoint(ep, port))
	if err != nil {
		return nil, err
	}

	session := &concealBindFallbackSession{
		parent: b,
		key:    key,
		ep:     ep,
		conn:   fallbackConn,
	}

	b.mu.Lock()
	if b.fallbackPort != port || b.fallbackPort == 0 {
		b.mu.Unlock()
		fallbackConn.Close()
		return nil, net.ErrClosed
	}
	if b.fallbackSessions == nil {
		b.fallbackSessions = make(map[string]*concealBindFallbackSession)
	}
	if existing := b.fallbackSessions[key]; existing != nil {
		b.mu.Unlock()
		fallbackConn.Close()
		return existing, nil
	}
	b.fallbackSessions[key] = session
	b.mu.Unlock()

	go session.relay()
	return session, nil
}

func (b *ConcealBind) removeFallbackSession(key string, session *concealBindFallbackSession) {
	b.mu.Lock()
	if b.fallbackSessions[key] == session {
		delete(b.fallbackSessions, key)
	}
	b.mu.Unlock()
}

func (b *ConcealBind) closeFallbackSessionsLocked() {
	for key, session := range b.fallbackSessions {
		session.close()
		delete(b.fallbackSessions, key)
	}
}

type concealBindFallbackSession struct {
	parent *ConcealBind
	key    string
	ep     Endpoint
	conn   *net.UDPConn
	once   sync.Once
}

func (s *concealBindFallbackSession) relay() {
	defer s.parent.removeFallbackSession(s.key, s)

	buf := make([]byte, 65535)
	for {
		n, err := s.conn.Read(buf)
		if err != nil {
			return
		}
		if err := s.parent.inner.Send([][]byte{buf[:n]}, s.ep); err != nil {
			return
		}
	}
}

func (s *concealBindFallbackSession) close() {
	s.once.Do(func() {
		s.conn.Close()
	})
}

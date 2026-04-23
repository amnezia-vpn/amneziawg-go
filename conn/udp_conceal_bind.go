package conn

import (
	"bytes"
	"sync"
	"sync/atomic"

	"github.com/amnezia-vpn/amneziawg-go/conceal"
)

var (
	_ Bind          = (*ConcealBind)(nil)
	_ Framable      = (*ConcealBind)(nil)
	_ Preludable    = (*ConcealBind)(nil)
	_ Masqueradable = (*ConcealBind)(nil)
)

type ConcealBind struct {
	inner Bind

	mu sync.Mutex

	bufPool sync.Pool

	framedOpts     conceal.FramedOpts
	preludeOpts    conceal.PreludeOpts
	masqueradeOpts conceal.MasqueradeOpts

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

			size, ok := pipeline.DecodeInPlace(packets[i], sizes[i])
			if !ok {
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
	return b.inner.Close()
}

func (b *ConcealBind) SetMark(mark uint32) error {
	return b.inner.SetMark(mark)
}

func (b *ConcealBind) Send(bufs [][]byte, ep Endpoint) error {
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

	for _, buf := range bufs {
		if err := pipeline.EmitPrelude(buf, func(packet []byte) error {
			return appendPacket(bytes.Clone(packet), nil)
		}); err != nil {
			return err
		}

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
	return b.inner.ParseEndpoint(s)
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

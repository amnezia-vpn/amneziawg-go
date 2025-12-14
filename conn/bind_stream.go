package conn

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
)

type streamPacketQueue struct {
	ep  *streamEndpoint
	err error
	buf [65535]byte
	n   int
}

func NewBindStream() *BindStream {
	return &BindStream{
		streamPacketPool: sync.Pool{
			New: func() any {
				return new(streamPacketQueue)
			},
		},
	}
}

var _ Bind = (*BindStream)(nil)

type BindStream struct {
	queue            chan *streamPacketQueue
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	streamPacketPool sync.Pool
	dialer           net.Dialer
	listenConfig     net.ListenConfig
}

func (b *BindStream) readFaucet() ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		select {
		case <-b.ctx.Done():
			return 0, io.EOF
		case streamPacket, ok := <-b.queue:
			if !ok {
				return 0, io.EOF
			}
			if streamPacket.err != nil {
				return 0, streamPacket.err
			}

			packet := streamPacket.buf[:streamPacket.n]

			copy(packets[0], packet)
			sizes[0] = streamPacket.n
			eps[0] = streamPacket.ep

			b.streamPacketPool.Put(streamPacket)
			return 1, nil
		}
	}
}

func (b *BindStream) readStream(ep *streamEndpoint) {
	defer b.wg.Done()

	for {
		select {
		case <-b.ctx.Done():
			return
		default:
		}

		if err := ep.DialDst(b.ctx, b.dialer); err != nil {
			continue
		}

		var err error

		sp := b.streamPacketPool.Get().(*streamPacketQueue)
		sp.ep = ep
		sp.n, err = ep.conn.Read(sp.buf[:])
		sp.err = err
		b.queue <- sp

		if err != nil {
			ep.Close()
			if !ep.mustDial {
				return
			}
		}
	}
}

func (b *BindStream) listen(port uint16) {
	defer b.wg.Done()

	for {
		select {
		case <-b.ctx.Done():
			return
		default:
		}

		listenDone := make(chan struct{})

		listener, err := b.listenConfig.Listen(b.ctx, "tcp", ":"+strconv.Itoa(int(port)))
		if err != nil {
			continue
		}

		b.wg.Add(1)
		go b.accept(listener, listenDone)

		select {
		case <-b.ctx.Done():
		case <-listenDone:
		}

		listener.Close()
	}
}

func (b *BindStream) accept(listener net.Listener, listenDone chan struct{}) {
	defer b.wg.Done()
	defer close(listenDone)

	for {
		select {
		case <-b.ctx.Done():
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			// log this error somewhere
			break
		}

		b.wg.Add(1)
		go b.handleAccepted(conn, listenDone)
	}
}

func (b *BindStream) handleAccepted(conn net.Conn, listenDone chan struct{}) {
	defer b.wg.Done()

	ep, err := streamEndpointFromConn(conn)
	if err != nil {
		// log something?
	}

	b.wg.Add(1)
	go b.readStream(ep)

	select {
	case <-b.ctx.Done():
	case <-listenDone:
	}

	conn.Close()
}

func (b *BindStream) Open(port uint16) (fns []ReceiveFunc, actualPort uint16, err error) {
	b.ctx, b.cancel = context.WithCancel(context.Background())
	b.queue = make(chan *streamPacketQueue, 1024)

	if port != 0 {
		b.wg.Add(1)
		go b.listen(port)
	}

	return []ReceiveFunc{b.readFaucet()}, port, nil
}

func (b *BindStream) SetMark(mark uint32) error {
	return nil
}

func (b *BindStream) Send(bufs [][]byte, ep Endpoint) error {
	streamEp := ep.(*streamEndpoint)

	select {
	case <-b.ctx.Done():
		return io.ErrClosedPipe
	default:
	}

	if err := streamEp.DialDst(b.ctx, b.dialer); err != nil {
		return nil
	}

	for _, buf := range bufs {
		if _, err := streamEp.conn.Write(buf); err != nil {
			streamEp.Close()
			return err
		}
	}

	return nil
}

func (b *BindStream) ParseEndpoint(s string) (Endpoint, error) {
	ep, err := streamEndpointFromAddr(s)
	if err != nil {
		return nil, err
	}

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		<-b.ctx.Done()
		ep.Close()
	}()

	b.wg.Add(1)
	go b.readStream(ep)

	return ep, nil
}

func (b *BindStream) Close() error {
	if b.cancel != nil {
		b.cancel()
	}

	b.wg.Wait()

	if b.queue != nil {
		close(b.queue)
	}

	return nil
}

func (b *BindStream) BatchSize() int {
	return 1
}

var _ Endpoint = (*streamEndpoint)(nil)

type streamEndpoint struct {
	conn     net.Conn
	dst      netip.AddrPort
	mustDial bool
	mutex    sync.Mutex
}

func streamEndpointFromConn(conn net.Conn) (*streamEndpoint, error) {
	ap, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse addr: %v", err)
	}

	return &streamEndpoint{
		conn: conn,
		dst:  ap,
	}, nil
}

func streamEndpointFromAddr(addr string) (*streamEndpoint, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve addr: %v", err)
	}

	return &streamEndpoint{
		dst:      tcpAddr.AddrPort(),
		mustDial: true,
	}, nil
}

func (e *streamEndpoint) DialDst(ctx context.Context, dial net.Dialer) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.conn != nil {
		return nil
	}

	conn, err := dial.DialContext(ctx, "tcp", e.dst.String())
	if err != nil {
		return fmt.Errorf("failed to dial context: %v", err)
	}

	ap, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return fmt.Errorf("failed to dial context: %v", err)
	}

	e.conn = conn
	e.dst = ap

	return nil
}

func (e *streamEndpoint) Close() {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.conn != nil {
		e.conn.Close()
		e.conn = nil
	}
}

func (e *streamEndpoint) DstToString() string {
	return e.dst.String()
}

func (e *streamEndpoint) DstToBytes() []byte {
	b, _ := e.dst.MarshalBinary()
	return b
}

func (e *streamEndpoint) DstIP() netip.Addr {
	return e.dst.Addr()
}

func (e *streamEndpoint) ClearSrc() {
}

func (e *streamEndpoint) SrcToString() string {
	return ""
}

func (e *streamEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

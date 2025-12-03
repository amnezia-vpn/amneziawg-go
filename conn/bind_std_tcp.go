package conn

import (
	"context"
	"errors"
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

func NewBindStdStream() *BindStdStream {
	return &BindStdStream{
		queue: make(chan *streamPacketQueue),
		streamPacketPool: sync.Pool{
			New: func() any {
				return new(streamPacketQueue)
			},
		},
	}
}

var _ Bind = (*BindStdStream)(nil)

type BindStdStream struct {
	queue            chan *streamPacketQueue
	ctx              context.Context
	cancel           context.CancelFunc
	streamPacketPool sync.Pool
	dialer           net.Dialer
	listenConfig     net.ListenConfig
}

func (b *BindStdStream) readFaucet() ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		select {
		case <-b.ctx.Done():
			return 0, io.ErrClosedPipe
		case streamPacket := <-b.queue:
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

func (b *BindStdStream) readStream(ep *streamEndpoint) {
	for {
		if ep.conn == nil {
			conn, err := b.dialer.DialContext(b.ctx, "tcp", ep.dialAddr)
			if err != nil {
				continue
			}

			ap, err := netip.ParseAddrPort(conn.RemoteAddr().String())
			if err != nil {
				continue
			}

			ep.conn = conn
			ep.dst = ap
		}

		sp := b.streamPacketPool.Get().(*streamPacketQueue)
		sp.n, sp.err = ep.conn.Read(sp.buf[:])
		sp.ep = ep
		b.queue <- sp

		if sp.err != nil {
			ep.conn = nil

			select {
			case <-b.ctx.Done():
				break
			default:
			}

			if ep.dialAddr == "" {
				break
			}
		}
	}
}

func (b *BindStdStream) accept(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			break
		}

		ap, err := netip.ParseAddrPort(conn.RemoteAddr().String())
		if err != nil {
			continue
		}

		ep := &streamEndpoint{
			conn: conn,
			dst:  ap,
		}

		go b.readStream(ep)
	}
}

func (b *BindStdStream) Open(port uint16) (fns []ReceiveFunc, actualPort uint16, err error) {
	b.ctx, b.cancel = context.WithCancel(context.Background())

	if port != 0 {
		listener, err := b.listenConfig.Listen(b.ctx, "tcp", ":"+strconv.Itoa(int(port)))
		if err != nil {
			return nil, port, err
		}

		go b.accept(listener)
	}

	return []ReceiveFunc{b.readFaucet()}, port, nil
}

func (b *BindStdStream) SetMark(mark uint32) error {
	return nil
}

func (b *BindStdStream) Send(bufs [][]byte, ep Endpoint) error {
	streamEp := ep.(*streamEndpoint)

	var errs []error
	for _, buf := range bufs {
		if _, err := streamEp.conn.Write(buf); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func (b *BindStdStream) ParseEndpoint(s string) (Endpoint, error) {
	ep := &streamEndpoint{
		dialAddr: s,
	}

	go b.readStream(ep)

	return ep, nil
}

func (b *BindStdStream) Close() error {
	if b.cancel != nil {
		b.cancel()
	}
	return nil
}

func (b *BindStdStream) BatchSize() int {
	return 1
}

var _ Endpoint = (*streamEndpoint)(nil)

type streamEndpoint struct {
	conn     net.Conn
	dst      netip.AddrPort
	dialAddr string
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

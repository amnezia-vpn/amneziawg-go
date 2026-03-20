package conceal

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"

	"golang.org/x/net/ipv4"
)

type FramedOpts struct {
	H1           *RangedHeader
	H2           *RangedHeader
	H3           *RangedHeader
	H4           *RangedHeader
	S1           int
	S2           int
	S3           int
	S4           int
	HeaderCompat bool
}

func (o *FramedOpts) HasIntersections() bool {
	headers := []*RangedHeader{o.H1, o.H2, o.H3, o.H4}

	for i := range len(headers) {
		left := headers[i]
		if left == nil {
			continue
		}

		for j := i + 1; j < len(headers); j++ {
			right := headers[j]
			if right == nil {
				continue
			}

			if left.start <= right.end && right.start <= left.end {
				return true
			}
		}
	}

	return false
}

func newFrameEncoding(opts FramedOpts) (e frameEncoding, ok bool) {
	e = frameEncoding{}

	if opts.H1 != nil {
		e.header.initial = *opts.H1
		ok = true
	} else {
		e.header.initial = RangedHeader{WireguardMsgInitiationType, WireguardMsgInitiationType}
	}

	if opts.H2 != nil {
		e.header.response = *opts.H2
		ok = true
	} else {
		e.header.response = RangedHeader{WireguardMsgResponseType, WireguardMsgResponseType}
	}

	if opts.H3 != nil {
		e.header.cookie = *opts.H3
		ok = true
	} else {
		e.header.cookie = RangedHeader{WireguardMsgCookieReplyType, WireguardMsgCookieReplyType}
	}

	if opts.H4 != nil {
		e.header.transport = *opts.H4
		ok = true
	} else {
		e.header.transport = RangedHeader{WireguardMsgTransportType, WireguardMsgTransportType}
	}

	if opts.S1 != 0 {
		e.padding.initial = opts.S1
		ok = true
	}

	if opts.S2 != 0 {
		e.padding.response = opts.S2
		ok = true
	}

	if opts.S3 != 0 {
		e.padding.cookie = opts.S3
		ok = true
	}

	if opts.S4 != 0 {
		e.padding.transport = opts.S4
		ok = true
	}

	e.compat = opts.HeaderCompat
	return e, ok
}

type frameEncoding struct {
	header struct {
		initial   RangedHeader
		response  RangedHeader
		cookie    RangedHeader
		transport RangedHeader
	}
	padding struct {
		initial   int
		response  int
		cookie    int
		transport int
	}
	compat bool
}

func encodeOne(dst, src []byte, header RangedHeader, padding int) int {
	rand.Read(dst[:padding])
	dst = dst[padding:]

	binary.LittleEndian.PutUint32(dst[:4], header.Generate())
	dst = dst[4:]

	n := copy(dst, src[4:])
	return padding + 4 + n
}

func encodeOneCompat(dst, src []byte, padding int) int {
	rand.Read(dst[:padding])
	n := copy(dst[padding:], src)
	return padding + n
}

func (e *frameEncoding) Encode(dst, src []byte) int {
	if len(src) < 4 {
		return 0
	}

	header := binary.LittleEndian.Uint32(src[:4])

	if e.compat {
		if e.header.initial.Validate(header) {
			return encodeOneCompat(dst, src, e.padding.initial)
		} else if e.header.response.Validate(header) {
			return encodeOneCompat(dst, src, e.padding.response)
		} else if e.header.cookie.Validate(header) {
			return encodeOneCompat(dst, src, e.padding.cookie)
		} else if e.header.transport.Validate(header) {
			return encodeOneCompat(dst, src, e.padding.transport)
		}
	} else {
		switch src[0] {
		case WireguardMsgInitiationType:
			return encodeOne(dst, src, e.header.initial, e.padding.initial)
		case WireguardMsgResponseType:
			return encodeOne(dst, src, e.header.response, e.padding.response)
		case WireguardMsgCookieReplyType:
			return encodeOne(dst, src, e.header.cookie, e.padding.cookie)
		case WireguardMsgTransportType:
			return encodeOne(dst, src, e.header.transport, e.padding.transport)
		}
	}

	return 0
}

func decodeOneCompat(b []byte, header RangedHeader, padding int) int {
	bb := b[padding:]
	if !header.Validate(binary.LittleEndian.Uint32(bb[:4])) {
		return 0
	}

	return copy(b, bb)
}

func decodeOne(b []byte, header RangedHeader, padding int, originalHeader uint32) int {
	bb := b[padding:]
	if !header.Validate(binary.LittleEndian.Uint32(bb[:4])) {
		return 0
	}

	binary.LittleEndian.PutUint32(b[:4], originalHeader)
	n := copy(b[4:], bb[4:])

	return 4 + n
}

func (e *frameEncoding) Decode(b []byte) int {
	if len(b) == WireguardMsgInitiationSize+e.padding.initial {
		if e.compat {
			if n := decodeOneCompat(b, e.header.initial, e.padding.initial); n != 0 {
				return n
			}
		} else {
			if n := decodeOne(b, e.header.initial, e.padding.initial, WireguardMsgInitiationType); n != 0 {
				return n
			}
		}
	}

	if len(b) == WireguardMsgResponseSize+e.padding.response {
		if e.compat {
			if n := decodeOneCompat(b, e.header.response, e.padding.response); n != 0 {
				return n
			}
		} else {
			if n := decodeOne(b, e.header.response, e.padding.response, WireguardMsgResponseType); n != 0 {
				return n
			}
		}
	}

	if len(b) == WireguardMsgCookieReplySize+e.padding.cookie {
		if e.compat {
			if n := decodeOneCompat(b, e.header.cookie, e.padding.cookie); n != 0 {
				return n
			}
		} else {
			if n := decodeOne(b, e.header.cookie, e.padding.cookie, WireguardMsgCookieReplyType); n != 0 {
				return n
			}
		}
	}

	if len(b) >= WireguardMsgTransportMinSize+e.padding.transport {
		if e.compat {
			if n := decodeOneCompat(b, e.header.transport, e.padding.transport); n != 0 {
				return n
			}
		} else {
			if n := decodeOne(b, e.header.transport, e.padding.transport, WireguardMsgTransportType); n != 0 {
				return n
			}
		}
	}

	return len(b)
}

func NewFramedConn(conn net.Conn, pool *sync.Pool, opts FramedOpts) (c *FramedConn, ok bool) {
	enc, ok := newFrameEncoding(opts)
	if !ok {
		return nil, false
	}

	return &FramedConn{
		Conn: conn,
		pool: WrapBufferPool(pool),
		enc:  enc,
	}, true
}

type FramedConn struct {
	net.Conn
	pool *BufferPool
	enc  frameEncoding
}

func (c *FramedConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	n = c.enc.Decode(b[:n])
	return n, err
}

func (c *FramedConn) Write(b []byte) (n int, err error) {
	t := c.pool.Get()
	defer c.pool.Put(t)

	n = c.enc.Encode(t, b)
	diff := n - len(b)
	n, err = c.Conn.Write(t[:n])

	return max(n-diff, 0), err
}

func NewFramedUDPConn(conn UDPConn, pool *sync.Pool, opts FramedOpts) (c UDPConn, ok bool) {
	enc, ok := newFrameEncoding(opts)
	if !ok {
		return nil, false
	}

	return &FramedUDPConn{
		UDPConn: conn,
		pool:    WrapBufferPool(pool),
		enc:     enc,
	}, true
}

type FramedUDPConn struct {
	UDPConn
	pool *BufferPool
	enc  frameEncoding
}

func (c *FramedUDPConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	n, oobn, flags, addr, err = c.UDPConn.ReadMsgUDP(b, oob)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	n = c.enc.Decode(b[:n])
	return n, oobn, flags, addr, err
}

func (c *FramedUDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	t := c.pool.Get()
	defer c.pool.Put(t)

	n = c.enc.Encode(t, b)
	diff := n - len(b)
	n, oobn, err = c.UDPConn.WriteMsgUDP(t[:n], oob, addr)

	return max(n-diff, 0), oobn, err
}

func NewFramedBatchConn(conn BatchConn, pool *sync.Pool, opts FramedOpts) (c BatchConn, ok bool) {
	enc, ok := newFrameEncoding(opts)
	if !ok {
		return nil, false
	}

	return &FramedBatchConn{
		BatchConn: conn,
		pool:      WrapBufferPool(pool),
		enc:       enc,
	}, true
}

type FramedBatchConn struct {
	BatchConn
	pool *BufferPool
	enc  frameEncoding
}

func (c *FramedBatchConn) ReadBatch(ms []ipv4.Message, flags int) (n int, err error) {
	n, err = c.BatchConn.ReadBatch(ms, flags)
	if err != nil {
		return 0, err
	}

	for i := range ms[:n] {
		b := ms[i].Buffers[0][:ms[i].N]
		ms[i].N = c.enc.Decode(b)
	}

	return n, nil
}

func (c *FramedBatchConn) WriteBatch(ms []ipv4.Message, flags int) (n int, err error) {
	for i := range ms {
		t := c.pool.Get()
		defer c.pool.Put(t)

		n = c.enc.Encode(t, ms[i].Buffers[0])
		ms[i].Buffers[0] = t[:n]
	}

	// ms[i].N has incorrect N because the original data was modifier above
	// however, WG does not check this field, so this is fine
	return c.BatchConn.WriteBatch(ms, flags)
}

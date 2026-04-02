package conn

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const benchmarkConnMaxPacketSize = 65535

func BenchmarkConnEndpointDstToBytes(b *testing.B) {
	cases := []struct {
		name string
		ep   Endpoint
	}{
		{
			name: "StdNetEndpoint/IPv4",
			ep: &StdNetEndpoint{
				AddrPort: netip.MustParseAddrPort("127.0.0.1:51820"),
			},
		},
		{
			name: "StdNetEndpoint/IPv6",
			ep: &StdNetEndpoint{
				AddrPort: netip.MustParseAddrPort("[2001:db8::1]:51820"),
			},
		},
		{
			name: "streamEndpoint/IPv4",
			ep: &streamEndpoint{
				dst: netip.MustParseAddrPort("127.0.0.1:51820"),
			},
		},
		{
			name: "streamEndpoint/IPv6",
			ep: &streamEndpoint{
				dst: netip.MustParseAddrPort("[2001:db8::1]:51820"),
			},
		},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = tc.ep.DstToBytes()
			}
		})
	}
}

func BenchmarkConnCoalesceMessages(b *testing.B) {
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51820}
	ep := &StdNetEndpoint{
		AddrPort: addr.AddrPort(),
		src:      make([]byte, stickyControlSize),
	}
	cases := []struct {
		name string
		bufs [][]byte
	}{
		{
			name: "batch8/equal_transport",
			bufs: benchmarkConnEqualPayloads(8, 256),
		},
		{
			name: "batch8/mixed_transport",
			bufs: benchmarkConnMixedPayloads(8),
		},
		{
			name: "batch64/equal_transport",
			bufs: benchmarkConnEqualPayloads(64, 256),
		},
		{
			name: "batch64/mixed_transport",
			bufs: benchmarkConnMixedPayloads(64),
		},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			msgs := benchmarkConnMessages(len(tc.bufs), 2)
			benchmarkConnRunLoop(b, benchmarkConnTotalBytes(tc.bufs), nil, func() error {
				_ = coalesceMessages(addr, ep, tc.bufs, msgs, benchmarkConnSetGSOSize)
				return nil
			})
		})
	}
}

func BenchmarkConnSplitCoalescedMessages(b *testing.B) {
	cases := []struct {
		name       string
		build      func() []ipv6.Message
		firstMsgAt int
		bytesPerOp int
		reset      func([]ipv6.Message)
	}{
		{
			name:       "gso0",
			build:      func() []ipv6.Message { return benchmarkConnSplitMessages(1, 256, 0, 0) },
			firstMsgAt: 0,
			bytesPerOp: 256,
		},
		{
			name:       "gso16_8msgs",
			build:      func() []ipv6.Message { return benchmarkConnSplitMessages(8, 16, 16, 7) },
			firstMsgAt: 7,
			bytesPerOp: 8 * 16,
			reset: func(msgs []ipv6.Message) {
				for i := 0; i < len(msgs)-1; i++ {
					msgs[i].N = 0
					msgs[i].NN = 0
				}
				msgs[7].N = 8 * 16
				msgs[7].NN = 2
			},
		},
		{
			name:       "gso128_64msgs",
			build:      func() []ipv6.Message { return benchmarkConnSplitMessages(64, 128, 128, 63) },
			firstMsgAt: 63,
			bytesPerOp: 64 * 128,
			reset: func(msgs []ipv6.Message) {
				for i := 0; i < len(msgs)-1; i++ {
					msgs[i].N = 0
					msgs[i].NN = 0
				}
				msgs[63].N = 64 * 128
				msgs[63].NN = 2
			},
		},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			if tc.reset == nil {
				msgs := tc.build()
				benchmarkConnRunLoop(b, tc.bytesPerOp, nil, func() error {
					_, err := splitCoalescedMessages(msgs, tc.firstMsgAt, benchmarkConnGetGSOSize)
					return err
				})
				return
			}

			const fixtureRingSize = 256
			fixtures := make([][]ipv6.Message, fixtureRingSize)
			for i := range fixtures {
				fixtures[i] = tc.build()
			}

			b.ReportAllocs()
			if tc.bytesPerOp > 0 {
				b.SetBytes(int64(tc.bytesPerOp))
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if i > 0 && i%fixtureRingSize == 0 {
					b.StopTimer()
					for j := range fixtures {
						tc.reset(fixtures[j])
					}
					b.StartTimer()
				}

				_, err := splitCoalescedMessages(fixtures[i%fixtureRingSize], tc.firstMsgAt, benchmarkConnGetGSOSize)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkConnStdNetBindSend(b *testing.B) {
	cases := []struct {
		name     string
		batchLen int
		offload  bool
	}{
		{name: "gso_off/batch1", batchLen: 1, offload: false},
		{name: "gso_off/batch8", batchLen: 8, offload: false},
		{name: "gso_on/batch8", batchLen: 8, offload: true},
		{name: "gso_on/batch64", batchLen: 64, offload: true},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			bind := NewStdNetBind().(*StdNetBind)
			bind.ipv4 = &benchmarkConnUDPConn{}
			bind.ipv4PC = &benchmarkConnLinuxPacketConn{}
			bind.ipv4TxOffload = tc.offload

			endpoint := &StdNetEndpoint{
				AddrPort: netip.MustParseAddrPort("127.0.0.1:51820"),
				src:      make([]byte, stickyControlSize),
			}

			if !tc.offload {
				bufs := benchmarkConnSendPayloads(tc.batchLen, 256, false)
				benchmarkConnRunLoop(b, benchmarkConnTotalBytes(bufs), nil, func() error {
					return bind.Send(bufs, endpoint)
				})
				return
			}

			fixtures := make([]benchmarkConnSendFixture, benchmarkConnFixtureRingSize)
			for i := range fixtures {
				fixtures[i] = newBenchmarkConnSendFixture(tc.batchLen, 256, true)
			}
			benchmarkConnRunLoopWithFixtureRing(b, benchmarkConnTotalBytes(fixtures[0].bufs), fixtures, func(f benchmarkConnSendFixture) {
				benchmarkConnResetPayloadLens(f.bufs, f.lens)
			}, func(f benchmarkConnSendFixture) error {
				return bind.Send(f.bufs, endpoint)
			})
		})
	}
}

func BenchmarkConnStdNetBindReceive(b *testing.B) {
	cases := []struct {
		name      string
		batchSize int
		rxOffload bool
		reader    *benchmarkConnLinuxPacketConn
		conn      *benchmarkConnUDPConn
	}{
		{
			name:      "single",
			batchSize: 1,
			rxOffload: false,
			reader: &benchmarkConnLinuxPacketConn{
				readBatches: [][]benchmarkConnPacket{benchmarkConnBatchPackets(1, 256)},
			},
			conn: &benchmarkConnUDPConn{
				readPayloads: [][]byte{benchmarkConnPayload(256)},
			},
		},
		{
			name:      "batch",
			batchSize: 8,
			rxOffload: false,
			reader: &benchmarkConnLinuxPacketConn{
				readBatches: [][]benchmarkConnPacket{benchmarkConnBatchPackets(8, 256)},
			},
			conn: &benchmarkConnUDPConn{
				readPayloads: [][]byte{benchmarkConnPayload(256)},
			},
		},
		{
			name:      "batch_rx_offload",
			batchSize: 64,
			rxOffload: true,
			reader: &benchmarkConnLinuxPacketConn{
				readBatches: [][]benchmarkConnPacket{benchmarkConnCoalescedBatch(64, 256)},
			},
			conn: &benchmarkConnUDPConn{
				readPayloads: [][]byte{benchmarkConnPayload(256)},
			},
		},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			bind := NewStdNetBind().(*StdNetBind)
			bufs := make([][]byte, tc.batchSize)
			for i := range bufs {
				bufs[i] = make([]byte, benchmarkConnMaxPacketSize)
			}
			sizes := make([]int, tc.batchSize)
			eps := make([]Endpoint, tc.batchSize)

			benchmarkConnRunLoop(b, tc.batchSize*256, nil, func() error {
				_, err := bind.receiveIP(tc.reader, tc.conn, tc.rxOffload, bufs, sizes, eps)
				return err
			})
		})
	}
}

func benchmarkConnRunLoop(b *testing.B, bytesPerOp int, reset func(), op func() error) {
	b.Helper()
	b.ReportAllocs()
	if bytesPerOp > 0 {
		b.SetBytes(int64(bytesPerOp))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i > 0 && reset != nil {
			b.StopTimer()
			reset()
			b.StartTimer()
		}
		if err := op(); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkConnRunLoopWithFixtureRing[T any](b *testing.B, bytesPerOp int, fixtures []T, reset func(T), op func(T) error) {
	b.Helper()
	if len(fixtures) == 0 {
		b.Fatal("benchmark fixture ring must not be empty")
	}

	b.ReportAllocs()
	if bytesPerOp > 0 {
		b.SetBytes(int64(bytesPerOp))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i > 0 && i%len(fixtures) == 0 && reset != nil {
			b.StopTimer()
			for _, fixture := range fixtures {
				reset(fixture)
			}
			b.StartTimer()
		}
		if err := op(fixtures[i%len(fixtures)]); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkConnPayload(size int) []byte {
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i)
	}
	return payload
}

func benchmarkConnEqualPayloads(count, size int) [][]byte {
	bufs := make([][]byte, count)
	for i := range bufs {
		capacity := size
		if i == 0 {
			capacity = size * count
		}
		buf := make([]byte, size, capacity)
		for j := range buf {
			buf[j] = byte(j)
		}
		bufs[i] = buf
	}
	return bufs
}

func benchmarkConnMixedPayloads(count int) [][]byte {
	bufs := make([][]byte, count)
	for i := range bufs {
		size := 256
		if i%2 == 1 {
			size = 1280
		}
		capacity := size
		if i == 0 {
			capacity = size * count
		}
		buf := make([]byte, size, capacity)
		for j := range buf {
			buf[j] = byte(j)
		}
		bufs[i] = buf
	}
	return bufs
}

func benchmarkConnSendPayloads(count, size int, offload bool) [][]byte {
	bufs := make([][]byte, count)
	for i := range bufs {
		capacity := size
		if offload && i == 0 {
			capacity = size * count
		}
		buf := make([]byte, size, capacity)
		for j := range buf {
			buf[j] = byte(j)
		}
		bufs[i] = buf
	}
	return bufs
}

func benchmarkConnLengths(bufs [][]byte) []int {
	lens := make([]int, len(bufs))
	for i := range bufs {
		lens[i] = len(bufs[i])
	}
	return lens
}

func benchmarkConnResetPayloadLens(bufs [][]byte, lens []int) {
	for i := range bufs {
		bufs[i] = bufs[i][:lens[i]]
	}
}

const benchmarkConnFixtureRingSize = 256

type benchmarkConnSendFixture struct {
	bufs [][]byte
	lens []int
}

func newBenchmarkConnSendFixture(count, size int, offload bool) benchmarkConnSendFixture {
	bufs := benchmarkConnSendPayloads(count, size, offload)
	return benchmarkConnSendFixture{
		bufs: bufs,
		lens: benchmarkConnLengths(bufs),
	}
}

func benchmarkConnTotalBytes(bufs [][]byte) int {
	total := 0
	for _, buf := range bufs {
		total += len(buf)
	}
	return total
}

func benchmarkConnMessages(count int, oobCap int) []ipv6.Message {
	msgs := make([]ipv6.Message, count)
	for i := range msgs {
		msgs[i].Buffers = make([][]byte, 1)
		msgs[i].OOB = make([]byte, 0, oobCap)
	}
	return msgs
}

func benchmarkConnResetMessages(msgs []ipv6.Message) {
	for i := range msgs {
		msgs[i].Addr = nil
		msgs[i].N = 0
		msgs[i].NN = 0
		msgs[i].OOB = msgs[i].OOB[:0]
		msgs[i].Buffers[0] = nil
	}
}

func benchmarkConnSetGSOSize(control *[]byte, gsoSize uint16) {
	*control = (*control)[:cap(*control)]
	binary.LittleEndian.PutUint16(*control, gsoSize)
}

func benchmarkConnGetGSOSize(control []byte) (int, error) {
	if len(control) < 2 {
		return 0, nil
	}
	return int(binary.LittleEndian.Uint16(control)), nil
}

func benchmarkConnSplitMessages(numMsgs, segmentSize, gsoSize, sourceIndex int) []ipv6.Message {
	msgs := make([]ipv6.Message, numMsgs)
	for i := range msgs {
		bufSize := segmentSize
		if i == sourceIndex {
			bufSize = numMsgs * segmentSize
		}
		msgs[i].Buffers = [][]byte{make([]byte, bufSize)}
		msgs[i].OOB = make([]byte, 0, 2)
	}
	for i := 0; i < numMsgs*segmentSize; i++ {
		msgs[sourceIndex].Buffers[0][i] = byte(i)
	}
	msgs[sourceIndex].N = numMsgs * segmentSize
	if gsoSize > 0 {
		msgs[sourceIndex].OOB = msgs[sourceIndex].OOB[:2]
		binary.LittleEndian.PutUint16(msgs[sourceIndex].OOB, uint16(gsoSize))
		msgs[sourceIndex].NN = 2
	}
	return msgs
}

type benchmarkConnPacket struct {
	payload []byte
	oob     []byte
}

func benchmarkConnBatchPackets(count, size int) []benchmarkConnPacket {
	packets := make([]benchmarkConnPacket, count)
	for i := range packets {
		packets[i].payload = benchmarkConnPayload(size)
	}
	return packets
}

func benchmarkConnCoalescedBatch(count, segmentSize int) []benchmarkConnPacket {
	payload := make([]byte, count*segmentSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	oob := make([]byte, 2)
	binary.LittleEndian.PutUint16(oob, uint16(segmentSize))
	return []benchmarkConnPacket{
		{
			payload: payload,
			oob:     oob,
		},
	}
}

type benchmarkConnLinuxPacketConn struct {
	readBatches [][]benchmarkConnPacket
	readIndex   int
}

func (c *benchmarkConnLinuxPacketConn) ResetRead() {
	c.readIndex = 0
}

func (c *benchmarkConnLinuxPacketConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	if len(c.readBatches) == 0 {
		return 0, io.EOF
	}
	batch := c.readBatches[c.readIndex]
	c.readIndex++
	if c.readIndex == len(c.readBatches) {
		c.readIndex = 0
	}
	for i := range batch {
		msg := &ms[i]
		packet := batch[i]
		msg.N = copy(msg.Buffers[0], packet.payload)
		if cap(msg.OOB) < len(packet.oob) {
			msg.OOB = make([]byte, len(packet.oob))
		}
		msg.OOB = msg.OOB[:len(packet.oob)]
		copy(msg.OOB, packet.oob)
		msg.NN = len(packet.oob)
		msg.Addr = &net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 51820,
		}
	}
	for i := len(batch); i < len(ms); i++ {
		ms[i].N = 0
		ms[i].NN = 0
		ms[i].Addr = nil
		ms[i].OOB = ms[i].OOB[:0]
	}
	return len(batch), nil
}

func (c *benchmarkConnLinuxPacketConn) WriteBatch(ms []ipv4.Message, flags int) (int, error) {
	return len(ms), nil
}

type benchmarkConnUDPConn struct {
	readPayloads [][]byte
	readIndex    int
}

func (c *benchmarkConnUDPConn) ResetRead() {
	c.readIndex = 0
}

func (c *benchmarkConnUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, _, _, addr, err := c.ReadMsgUDP(p, nil)
	return n, addr, err
}

func (c *benchmarkConnUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	udpAddr, _ := addr.(*net.UDPAddr)
	n, _, err := c.WriteMsgUDP(p, nil, udpAddr)
	return n, err
}

func (c *benchmarkConnUDPConn) Close() error {
	return nil
}

func (c *benchmarkConnUDPConn) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 51820,
	}
}

func (c *benchmarkConnUDPConn) SetDeadline(time.Time) error {
	return nil
}

func (c *benchmarkConnUDPConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *benchmarkConnUDPConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *benchmarkConnUDPConn) SyscallConn() (syscall.RawConn, error) {
	return nil, nil
}

func (c *benchmarkConnUDPConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	if len(c.readPayloads) == 0 {
		return 0, 0, 0, nil, io.EOF
	}
	payload := c.readPayloads[c.readIndex]
	c.readIndex++
	if c.readIndex == len(c.readPayloads) {
		c.readIndex = 0
	}
	n = copy(b, payload)
	return n, 0, 0, &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 51820,
	}, nil
}

func (c *benchmarkConnUDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
	return len(b), len(oob), nil
}

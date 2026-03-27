package conceal

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

const (
	benchmarkMaxPacketSize   = 65535
	benchmarkBatchPoolSize   = 128
	benchmarkUDPListenPort   = 51820
	benchmarkFixtureRingSize = 256
)

var (
	benchmarkFramedOpts = FramedOpts{
		H1: benchmarkMustHeader("777"),
		H2: benchmarkMustHeader("778"),
		H3: benchmarkMustHeader("779"),
		H4: benchmarkMustHeader("780"),
		S1: 8,
		S2: 8,
		S3: 8,
		S4: 16,
	}
	benchmarkFramedCompatOpts = func() FramedOpts {
		opts := benchmarkFramedOpts
		opts.HeaderCompat = true
		return opts
	}()
	benchmarkMasqueradeRules = benchmarkMustRules("<dz be 2><d>")
	benchmarkPreludeOneRule  = PreludeOpts{
		RulesArr: [5]Rules{
			benchmarkMustRules("<b 0xaabb>"),
		},
	}
	benchmarkPreludeFiveRules = PreludeOpts{
		RulesArr: [5]Rules{
			benchmarkMustRules("<b 0xa1>"),
			benchmarkMustRules("<b 0xa2a3>"),
			benchmarkMustRules("<b 0xa4a5a6>"),
			benchmarkMustRules("<b 0xa7a8a9aa>"),
			benchmarkMustRules("<b 0xabacadaeaf>"),
		},
	}
	benchmarkPreludeRulesPlusJunk = PreludeOpts{
		Jc:   1,
		Jmin: 3,
		Jmax: 3,
		RulesArr: [5]Rules{
			benchmarkMustRules("<b 0xaabb>"),
		},
	}
	benchmarkPayloads = benchmarkBuildPayloadProfiles()
	benchmarkUDPAddr  = &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: benchmarkUDPListenPort,
	}

	benchmarkRandMu sync.Mutex
)

type benchmarkPayloadProfiles struct {
	initiation         []byte
	response           []byte
	cookie             []byte
	transportKeepalive []byte
	transportSmall     []byte
	transportMTU       []byte

	compatInitiation         []byte
	compatResponse           []byte
	compatCookie             []byte
	compatTransportKeepalive []byte
	compatTransportSmall     []byte
	compatTransportMTU       []byte
}

func benchmarkBuildPayloadProfiles() benchmarkPayloadProfiles {
	return benchmarkPayloadProfiles{
		initiation:               benchmarkMakePayload(WireguardMsgInitiationSize, WireguardMsgInitiationType),
		response:                 benchmarkMakePayload(WireguardMsgResponseSize, WireguardMsgResponseType),
		cookie:                   benchmarkMakePayload(WireguardMsgCookieReplySize, WireguardMsgCookieReplyType),
		transportKeepalive:       benchmarkMakePayload(WireguardMsgTransportMinSize, WireguardMsgTransportType),
		transportSmall:           benchmarkMakePayload(256, WireguardMsgTransportType),
		transportMTU:             benchmarkMakePayload(1280, WireguardMsgTransportType),
		compatInitiation:         benchmarkMakePayload(WireguardMsgInitiationSize, benchmarkFramedCompatOpts.H1.start),
		compatResponse:           benchmarkMakePayload(WireguardMsgResponseSize, benchmarkFramedCompatOpts.H2.start),
		compatCookie:             benchmarkMakePayload(WireguardMsgCookieReplySize, benchmarkFramedCompatOpts.H3.start),
		compatTransportKeepalive: benchmarkMakePayload(WireguardMsgTransportMinSize, benchmarkFramedCompatOpts.H4.start),
		compatTransportSmall:     benchmarkMakePayload(256, benchmarkFramedCompatOpts.H4.start),
		compatTransportMTU:       benchmarkMakePayload(1280, benchmarkFramedCompatOpts.H4.start),
	}
}

func benchmarkMakePayload(size int, header uint32) []byte {
	payload := make([]byte, size)
	binary.LittleEndian.PutUint32(payload[:4], header)
	for i := 4; i < len(payload); i++ {
		payload[i] = byte(i)
	}
	return payload
}

func benchmarkMustRules(spec string) Rules {
	rules, err := ParseRules(spec)
	if err != nil {
		panic(err)
	}
	return rules
}

func benchmarkMustHeader(spec string) *RangedHeader {
	header, err := NewRangedHeader(spec)
	if err != nil {
		panic(err)
	}
	return header
}

func benchmarkNewBufferPool() *sync.Pool {
	return &sync.Pool{
		New: func() any {
			return make([]byte, benchmarkMaxPacketSize)
		},
	}
}

func benchmarkNewMsgsPool() *sync.Pool {
	return &sync.Pool{
		New: func() any {
			msgs := make([]ipv4.Message, benchmarkBatchPoolSize)
			for i := range msgs {
				msgs[i].Buffers = make([][]byte, 1)
				msgs[i].OOB = make([]byte, 0)
			}
			return &msgs
		},
	}
}

func benchmarkMaxFramePadding(opts FramedOpts) int {
	maxPadding := opts.S1
	if opts.S2 > maxPadding {
		maxPadding = opts.S2
	}
	if opts.S3 > maxPadding {
		maxPadding = opts.S3
	}
	if opts.S4 > maxPadding {
		maxPadding = opts.S4
	}
	return maxPadding
}

func benchmarkEncodeFramedRecord(opts FramedOpts, payload []byte) []byte {
	enc, ok := newFrameEncoding(opts)
	if !ok {
		panic("framed benchmark encoding unavailable")
	}
	buf := make([]byte, len(payload)+benchmarkMaxFramePadding(opts))
	n := enc.Encode(buf, payload)
	if n == 0 {
		panic("framed benchmark encoding failed")
	}
	return append([]byte(nil), buf[:n]...)
}

func benchmarkEncodeMasqueradeRecord(rules Rules, payload []byte) []byte {
	pool := benchmarkNewBufferPool()
	ctx := writeContext{
		FlexBuffer: WrapFlexBuffer(payload),
		BufferPool: WrapBufferPool(pool),
	}
	tmp := pool.Get().([]byte)
	defer pool.Put(tmp)

	w := newSliceWriter(tmp)
	if err := rules.Write(&w, &ctx); err != nil {
		panic(err)
	}
	return append([]byte(nil), w.Bytes()...)
}

func benchmarkEncodeStreamRecords(rules Rules, records ...[]byte) []byte {
	var out bytes.Buffer
	for _, record := range records {
		out.Write(benchmarkEncodeMasqueradeRecord(rules, record))
	}
	return out.Bytes()
}

func benchmarkRepeatPayload(payload []byte, count int) [][]byte {
	payloads := make([][]byte, count)
	for i := range payloads {
		payloads[i] = payload
	}
	return payloads
}

func benchmarkInitiationBatch(batchSize int) [][]byte {
	payloads := make([][]byte, batchSize)
	if batchSize == 0 {
		return payloads
	}
	payloads[0] = benchmarkPayloads.initiation
	for i := 1; i < len(payloads); i++ {
		payloads[i] = benchmarkPayloads.transportSmall
	}
	return payloads
}

func benchmarkTotalBytes(payloads [][]byte) int {
	total := 0
	for _, payload := range payloads {
		total += len(payload)
	}
	return total
}

func benchmarkAverageBytes(payloads ...[]byte) int {
	if len(payloads) == 0 {
		return 0
	}
	total := 0
	for _, payload := range payloads {
		total += len(payload)
	}
	return total / len(payloads)
}

func benchmarkAverageInts(values ...int) int {
	if len(values) == 0 {
		return 0
	}
	total := 0
	for _, value := range values {
		total += value
	}
	return total / len(values)
}

func benchmarkFullMatrixEnabled() bool {
	return os.Getenv("AMNEZWG_BENCH_FULL") != ""
}

func benchmarkRunLoop(b *testing.B, bytesPerOp int, reset func(), op func() error) {
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

func benchmarkRunLoopWithFixtureRing[T any](b *testing.B, bytesPerOp int, fixtures []T, reset func(T), op func(T) error) {
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

func benchmarkUseDeterministicRand(b *testing.B) {
	b.Helper()
	benchmarkRandMu.Lock()
	oldReader := crand.Reader
	crand.Reader = &benchmarkDeterministicReader{state: 1}
	b.Cleanup(func() {
		crand.Reader = oldReader
		benchmarkRandMu.Unlock()
	})
}

type benchmarkDeterministicReader struct {
	state uint64
}

func (r *benchmarkDeterministicReader) Read(p []byte) (int, error) {
	x := r.state
	if x == 0 {
		x = 1
	}
	for i := range p {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		p[i] = byte(x)
	}
	r.state = x
	return len(p), nil
}

type benchmarkStreamConn struct {
	readBuf      []byte
	readOff      int
	readChunks   [][]byte
	readChunkAt  int
	readChunkOff int
}

func newBenchmarkStreamConn(readBuf []byte) *benchmarkStreamConn {
	return &benchmarkStreamConn{readBuf: readBuf}
}

func newBenchmarkStreamChunksConn(readChunks [][]byte) *benchmarkStreamConn {
	return &benchmarkStreamConn{readChunks: readChunks}
}

func (c *benchmarkStreamConn) ResetRead() {
	c.readOff = 0
	c.readChunkAt = 0
	c.readChunkOff = 0
}

func (c *benchmarkStreamConn) Read(p []byte) (int, error) {
	if len(c.readChunks) > 0 {
		chunk := c.readChunks[c.readChunkAt]
		if c.readChunkOff >= len(chunk) {
			c.readChunkAt++
			if c.readChunkAt == len(c.readChunks) {
				c.readChunkAt = 0
			}
			c.readChunkOff = 0
			chunk = c.readChunks[c.readChunkAt]
		}
		n := copy(p, chunk[c.readChunkOff:])
		c.readChunkOff += n
		if c.readChunkOff == len(chunk) {
			c.readChunkAt++
			if c.readChunkAt == len(c.readChunks) {
				c.readChunkAt = 0
			}
			c.readChunkOff = 0
		}
		return n, nil
	}
	if len(c.readBuf) == 0 {
		return 0, io.EOF
	}
	if c.readOff >= len(c.readBuf) {
		c.readOff = 0
	}
	n := copy(p, c.readBuf[c.readOff:])
	c.readOff += n
	return n, nil
}

func (c *benchmarkStreamConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c *benchmarkStreamConn) Close() error {
	return nil
}

func (c *benchmarkStreamConn) LocalAddr() net.Addr {
	return benchmarkUDPAddr
}

func (c *benchmarkStreamConn) RemoteAddr() net.Addr {
	return benchmarkUDPAddr
}

func (c *benchmarkStreamConn) SetDeadline(time.Time) error {
	return nil
}

func (c *benchmarkStreamConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *benchmarkStreamConn) SetWriteDeadline(time.Time) error {
	return nil
}

type benchmarkUDPConn struct {
	readPayloads [][]byte
	readIndex    int
}

func newBenchmarkUDPConn(readPayloads [][]byte) *benchmarkUDPConn {
	return &benchmarkUDPConn{readPayloads: readPayloads}
}

func (c *benchmarkUDPConn) ResetRead() {
	c.readIndex = 0
}

func (c *benchmarkUDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, _, _, udpAddr, err := c.ReadMsgUDP(p, nil)
	return n, udpAddr, err
}

func (c *benchmarkUDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	udpAddr, _ := addr.(*net.UDPAddr)
	n, _, err = c.WriteMsgUDP(p, nil, udpAddr)
	return n, err
}

func (c *benchmarkUDPConn) Close() error {
	return nil
}

func (c *benchmarkUDPConn) LocalAddr() net.Addr {
	return benchmarkUDPAddr
}

func (c *benchmarkUDPConn) SetDeadline(time.Time) error {
	return nil
}

func (c *benchmarkUDPConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *benchmarkUDPConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *benchmarkUDPConn) SyscallConn() (syscall.RawConn, error) {
	return nil, nil
}

func (c *benchmarkUDPConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	if len(c.readPayloads) == 0 {
		return 0, 0, 0, nil, io.EOF
	}
	payload := c.readPayloads[c.readIndex]
	c.readIndex++
	if c.readIndex == len(c.readPayloads) {
		c.readIndex = 0
	}
	n = copy(b, payload)
	return n, 0, 0, benchmarkUDPAddr, nil
}

func (c *benchmarkUDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	return len(b), len(oob), nil
}

type benchmarkBatchPacket struct {
	payload []byte
	oob     []byte
	addr    *net.UDPAddr
}

type benchmarkBatchConn struct {
	readBatches [][]benchmarkBatchPacket
	readIndex   int
}

func newBenchmarkBatchConn(readBatches [][]benchmarkBatchPacket) *benchmarkBatchConn {
	return &benchmarkBatchConn{readBatches: readBatches}
}

func (c *benchmarkBatchConn) ResetRead() {
	c.readIndex = 0
}

func (c *benchmarkBatchConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	if len(c.readBatches) == 0 {
		return 0, io.EOF
	}
	batch := c.readBatches[c.readIndex]
	c.readIndex++
	if c.readIndex == len(c.readBatches) {
		c.readIndex = 0
	}
	for i := range batch {
		packet := batch[i]
		msg := &ms[i]
		msg.N = copy(msg.Buffers[0], packet.payload)
		if cap(msg.OOB) < len(packet.oob) {
			panic("benchmark batch OOB buffer too small")
		}
		msg.OOB = msg.OOB[:len(packet.oob)]
		copy(msg.OOB, packet.oob)
		msg.NN = len(packet.oob)
		msg.Addr = packet.addr
	}
	for i := len(batch); i < len(ms); i++ {
		ms[i].N = 0
		ms[i].NN = 0
		ms[i].Addr = nil
		ms[i].OOB = ms[i].OOB[:0]
	}
	return len(batch), nil
}

func (c *benchmarkBatchConn) WriteBatch(ms []ipv4.Message, flags int) (int, error) {
	return len(ms), nil
}

func benchmarkBatchPackets(payloads [][]byte) []benchmarkBatchPacket {
	packets := make([]benchmarkBatchPacket, len(payloads))
	for i, payload := range payloads {
		packets[i] = benchmarkBatchPacket{
			payload: payload,
			addr:    benchmarkUDPAddr,
		}
	}
	return packets
}

func benchmarkNewBatchReadMessages(count int, oobCap int) []ipv4.Message {
	msgs := make([]ipv4.Message, count)
	for i := range msgs {
		msgs[i].Buffers = make([][]byte, 1)
		msgs[i].Buffers[0] = make([]byte, benchmarkMaxPacketSize)
		msgs[i].OOB = make([]byte, 0, oobCap)
	}
	return msgs
}

type benchmarkBatchWriteFixture struct {
	msgs     []ipv4.Message
	payloads [][]byte
	addr     *net.UDPAddr
}

func newBenchmarkBatchWriteFixture(payloads [][]byte, oobCap int) *benchmarkBatchWriteFixture {
	fixture := &benchmarkBatchWriteFixture{
		msgs:     make([]ipv4.Message, len(payloads)),
		payloads: payloads,
		addr:     benchmarkUDPAddr,
	}
	for i := range fixture.msgs {
		fixture.msgs[i].Buffers = make([][]byte, 1)
		fixture.msgs[i].OOB = make([]byte, 0, oobCap)
	}
	fixture.Reset()
	return fixture
}

func (f *benchmarkBatchWriteFixture) Reset() {
	for i, payload := range f.payloads {
		f.msgs[i].Buffers[0] = payload
		f.msgs[i].N = len(payload)
		f.msgs[i].NN = 0
		f.msgs[i].Addr = f.addr
		f.msgs[i].OOB = f.msgs[i].OOB[:0]
	}
}

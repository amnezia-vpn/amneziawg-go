package conn

import (
	"bytes"
	"encoding/binary"
	"net"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conceal"
)

func TestStdNetBindUDPPipelineOrder(t *testing.T) {
	bind := NewStdNetBind().(*StdNetBind)
	bind.SetMasqueradeOpts(conceal.MasqueradeOpts{
		RulesIn:  mustParseRules(t, "<dz be 2><d>"),
		RulesOut: mustParseRules(t, "<dz be 2><d>"),
	})
	bind.SetFramedOpts(conceal.FramedOpts{H1: mustHeader(t, "777")})
	bind.SetPreludeOpts(conceal.PreludeOpts{
		RulesArr: [5]conceal.Rules{mustParseRules(t, "<b 0xaabb>")},
	})

	got := bind.udpConcealPipeline().names()
	want := []string{"masquerade", "framed", "prelude"}
	if !slices.Equal(got, want) {
		t.Fatalf("udp pipeline = %v, want %v", got, want)
	}
}

func TestStdNetBindUDPPreludeStillEmitsJunk(t *testing.T) {
	bind := NewStdNetBind().(*StdNetBind)
	bind.SetPreludeOpts(conceal.PreludeOpts{
		Jc:   1,
		Jmin: 3,
		Jmax: 3,
		RulesArr: [5]conceal.Rules{
			mustParseRules(t, "<b 0xaabb>"),
		},
	})

	conn := &recordingUDPConn{}
	upgraded := bind.upgradeUDPConn(conn)
	initiation := makeInitiationPacket()

	if _, _, err := upgraded.WriteMsgUDP(initiation, nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51820}); err != nil {
		t.Fatalf("udp write failed: %v", err)
	}

	if len(conn.writes) != 3 {
		t.Fatalf("udp write count = %d, want 3", len(conn.writes))
	}
	if !bytes.Equal(conn.writes[0], []byte{0xaa, 0xbb}) {
		t.Fatalf("udp decoy record = %x, want aabb", conn.writes[0])
	}
	if len(conn.writes[1]) != 3 {
		t.Fatalf("udp junk length = %d, want 3", len(conn.writes[1]))
	}
	if !bytes.Equal(conn.writes[2], initiation) {
		t.Fatalf("udp initiation payload changed")
	}
}

func TestBindStreamPipelineUsesRecordLayer(t *testing.T) {
	bind := newRecordAwareBind(t)

	got := bind.streamConcealPipeline().names()
	want := []string{"record", "prelude", "framed"}
	if !slices.Equal(got, want) {
		t.Fatalf("stream pipeline = %v, want %v", got, want)
	}
}

func TestBindStreamPipelineOmitsPreludeWithoutBidirectionalRecords(t *testing.T) {
	bind := NewBindStream()
	bind.SetMasqueradeOpts(conceal.MasqueradeOpts{
		RulesOut: mustParseRules(t, "<dz be 2><d>"),
	})
	bind.SetFramedOpts(conceal.FramedOpts{H1: mustHeader(t, "777")})
	bind.SetPreludeOpts(conceal.PreludeOpts{
		RulesArr: [5]conceal.Rules{mustParseRules(t, "<b 0xaabb>")},
	})

	got := bind.streamConcealPipeline().names()
	want := []string{"record", "framed"}
	if !slices.Equal(got, want) {
		t.Fatalf("stream pipeline without bidirectional records = %v, want %v", got, want)
	}
}

func TestBindStreamPipelineOmitsPreludeForTCPJunkOnlyConfig(t *testing.T) {
	bind := NewBindStream()
	bind.SetMasqueradeOpts(conceal.MasqueradeOpts{
		RulesIn:  mustParseRules(t, "<dz be 2><d>"),
		RulesOut: mustParseRules(t, "<dz be 2><d>"),
	})
	bind.SetFramedOpts(conceal.FramedOpts{H1: mustHeader(t, "777")})
	bind.SetPreludeOpts(conceal.PreludeOpts{
		Jc:   1,
		Jmin: 2,
		Jmax: 2,
	})

	got := bind.streamConcealPipeline().names()
	want := []string{"record", "framed"}
	if !slices.Equal(got, want) {
		t.Fatalf("stream pipeline with tcp junk only = %v, want %v", got, want)
	}
}

func TestBindStreamTCPPreludeInjectsBeforeEveryInitiation(t *testing.T) {
	senderRaw, receiverRaw := net.Pipe()
	defer senderRaw.Close()
	defer receiverRaw.Close()

	bind := newRecordAwareBind(t)
	sender := bind.upgradeConn(senderRaw)
	receiver := mustRecordConn(t, receiverRaw, &bind.bufferPool, conceal.MasqueradeOpts{
		RulesIn: mustParseRules(t, "<dz be 2><d>"),
	})

	initiation := makeInitiationPacket()

	writeErr := make(chan error, 1)
	go func() {
		_, err := sender.Write(initiation)
		writeErr <- err
	}()

	prelude := readRecord(t, receiver, 16)
	if !bytes.Equal(prelude, []byte{0xaa, 0xbb}) {
		t.Fatalf("prelude record = %x, want aabb", prelude)
	}

	firstInit := readRecord(t, receiver, len(initiation))
	if gotHeader := binary.LittleEndian.Uint32(firstInit[:4]); gotHeader != 777 {
		t.Fatalf("first initiation header = %d, want 777", gotHeader)
	}

	if err := <-writeErr; err != nil {
		t.Fatalf("first write failed: %v", err)
	}

	writeErr = make(chan error, 1)
	go func() {
		_, err := sender.Write(initiation)
		writeErr <- err
	}()

	secondPrelude := readRecord(t, receiver, 16)
	if !bytes.Equal(secondPrelude, []byte{0xaa, 0xbb}) {
		t.Fatalf("second prelude record = %x, want aabb", secondPrelude)
	}

	secondInit := readRecord(t, receiver, len(initiation))
	if gotHeader := binary.LittleEndian.Uint32(secondInit[:4]); gotHeader != 777 {
		t.Fatalf("second initiation header = %d, want 777", gotHeader)
	}

	if err := <-writeErr; err != nil {
		t.Fatalf("second write failed: %v", err)
	}
}

func TestBindStreamTCPPreludeSkipsNonInitiationRecords(t *testing.T) {
	senderRaw, receiverRaw := net.Pipe()
	defer senderRaw.Close()
	defer receiverRaw.Close()

	bind := newRecordAwareBind(t)
	sender := bind.upgradeConn(senderRaw)
	receiver := mustRecordConn(t, receiverRaw, &bind.bufferPool, conceal.MasqueradeOpts{
		RulesIn: mustParseRules(t, "<dz be 2><d>"),
	})

	transport := makeTransportPacket()
	writeErr := make(chan error, 1)
	go func() {
		_, err := sender.Write(transport)
		writeErr <- err
	}()

	gotTransport := readRecord(t, receiver, len(transport))
	if gotHeader := binary.LittleEndian.Uint32(gotTransport[:4]); gotHeader != 779 {
		t.Fatalf("transport header = %d, want 779", gotHeader)
	}

	if err := <-writeErr; err != nil {
		t.Fatalf("transport write failed: %v", err)
	}

	if err := receiver.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	buf := make([]byte, len(transport))
	if _, err := receiver.ReadRecord(buf); err == nil {
		t.Fatal("expected no extra prelude records for transport write")
	}
}

func TestBindStreamTCPPreludeDropsInjectedDecoysOnRead(t *testing.T) {
	senderRaw, receiverRaw := net.Pipe()
	defer senderRaw.Close()
	defer receiverRaw.Close()

	bind := newRecordAwareBind(t)
	sender := bind.upgradeConn(senderRaw)
	receiver := bind.upgradeConn(receiverRaw)

	initiation := makeInitiationPacket()
	writeErr := make(chan error, 1)
	go func() {
		_, err := sender.Write(initiation)
		writeErr <- err
	}()

	got := readPacket(t, receiver, len(initiation))
	if !bytes.Equal(got, initiation) {
		t.Fatalf("initiation payload changed after dropping decoys")
	}

	if err := <-writeErr; err != nil {
		t.Fatalf("write failed: %v", err)
	}
}

func TestBindStreamTCPPreludeDropsLeadingInvalidRecords(t *testing.T) {
	senderRaw, receiverRaw := net.Pipe()
	defer senderRaw.Close()
	defer receiverRaw.Close()

	bind := newRecordAwareBind(t)
	receiver := bind.upgradeConn(receiverRaw)

	recordWriter := mustRecordConn(t, senderRaw, &bind.bufferPool, conceal.MasqueradeOpts{
		RulesOut: mustParseRules(t, "<dz be 2><d>"),
	})
	framedWriter, ok := conceal.NewFramedConn(recordWriter, &bind.bufferPool, bind.framedOpts)
	if !ok {
		t.Fatal("expected framed writer")
	}

	initiation := makeInitiationPacket()
	writeErr := make(chan error, 1)
	go func() {
		if _, err := recordWriter.WriteRecord([]byte{0xde, 0xad}); err != nil {
			writeErr <- err
			return
		}
		if _, err := recordWriter.WriteRecord([]byte{0xbe, 0xef, 0x01}); err != nil {
			writeErr <- err
			return
		}
		_, err := framedWriter.Write(initiation)
		writeErr <- err
	}()

	got := readPacket(t, receiver, len(initiation))
	if !bytes.Equal(got, initiation) {
		t.Fatalf("read-side did not recover after invalid leading records")
	}

	if err := <-writeErr; err != nil {
		t.Fatalf("write failed: %v", err)
	}
}

func TestBindStreamTCPPreludePassesResponseAndTransportRecords(t *testing.T) {
	senderRaw, receiverRaw := net.Pipe()
	defer senderRaw.Close()
	defer receiverRaw.Close()

	bind := newRecordAwareBind(t)
	sender := bind.upgradeConn(senderRaw)
	receiver := bind.upgradeConn(receiverRaw)

	response := makeResponsePacket()
	sendAndAssertRoundTrip(t, sender, receiver, response)

	transport := makeTransportPacket()
	sendAndAssertRoundTrip(t, sender, receiver, transport)
}

func newRecordAwareBind(t *testing.T) *BindStream {
	t.Helper()

	rules := mustParseRules(t, "<dz be 2><d>")
	bind := NewBindStream()
	bind.SetMasqueradeOpts(conceal.MasqueradeOpts{
		RulesIn:  rules,
		RulesOut: rules,
	})
	bind.SetFramedOpts(conceal.FramedOpts{
		H1: mustHeader(t, "777"),
		H2: mustHeader(t, "778"),
		H4: mustHeader(t, "779"),
	})
	bind.SetPreludeOpts(conceal.PreludeOpts{
		Jc:   1,
		Jmin: 2,
		Jmax: 2,
		RulesArr: [5]conceal.Rules{
			mustParseRules(t, "<b 0xaabb>"),
		},
	})
	return bind
}

func sendAndAssertRoundTrip(t *testing.T, sender, receiver net.Conn, packet []byte) {
	t.Helper()

	writeErr := make(chan error, 1)
	go func() {
		_, err := sender.Write(packet)
		writeErr <- err
	}()

	got := readPacket(t, receiver, len(packet))
	if !bytes.Equal(got, packet) {
		t.Fatalf("round-trip payload mismatch")
	}

	if err := <-writeErr; err != nil {
		t.Fatalf("write failed: %v", err)
	}
}

func mustRecordConn(t *testing.T, conn net.Conn, pool *sync.Pool, opts conceal.MasqueradeOpts) *conceal.MasqueradeConn {
	t.Helper()

	recordConn, ok := conceal.NewMasqueradeConn(conn, pool, opts)
	if !ok {
		t.Fatal("expected record connection")
	}
	return recordConn
}

func mustParseRules(t *testing.T, spec string) conceal.Rules {
	t.Helper()

	rules, err := conceal.ParseRules(spec)
	if err != nil {
		t.Fatalf("parse rules %q: %v", spec, err)
	}
	return rules
}

func mustHeader(t *testing.T, spec string) *conceal.RangedHeader {
	t.Helper()

	header, err := conceal.NewRangedHeader(spec)
	if err != nil {
		t.Fatalf("parse header %q: %v", spec, err)
	}
	return header
}

func makeInitiationPacket() []byte {
	packet := make([]byte, conceal.WireguardMsgInitiationSize)
	binary.LittleEndian.PutUint32(packet[:4], conceal.WireguardMsgInitiationType)
	for i := 4; i < len(packet); i++ {
		packet[i] = byte(i)
	}
	return packet
}

func makeResponsePacket() []byte {
	packet := make([]byte, conceal.WireguardMsgResponseSize)
	binary.LittleEndian.PutUint32(packet[:4], conceal.WireguardMsgResponseType)
	for i := 4; i < len(packet); i++ {
		packet[i] = byte(i)
	}
	return packet
}

func makeTransportPacket() []byte {
	packet := make([]byte, conceal.WireguardMsgTransportMinSize)
	binary.LittleEndian.PutUint32(packet[:4], conceal.WireguardMsgTransportType)
	for i := 4; i < len(packet); i++ {
		packet[i] = byte(i)
	}
	return packet
}

func readPacket(t *testing.T, conn net.Conn, size int) []byte {
	t.Helper()

	buf := make([]byte, size)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read packet: %v", err)
	}
	return slices.Clone(buf[:n])
}

func readRecord(t *testing.T, conn interface{ ReadRecord([]byte) (int, error) }, size int) []byte {
	t.Helper()

	buf := make([]byte, size)
	n, err := conn.ReadRecord(buf)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	return slices.Clone(buf[:n])
}

type recordingUDPConn struct {
	writes [][]byte
}

func (c *recordingUDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, nil, net.ErrClosed
}

func (c *recordingUDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.writes = append(c.writes, bytes.Clone(p))
	return len(p), nil
}

func (c *recordingUDPConn) Close() error {
	return nil
}

func (c *recordingUDPConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *recordingUDPConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *recordingUDPConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *recordingUDPConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *recordingUDPConn) SyscallConn() (syscall.RawConn, error) {
	return nil, nil
}

func (c *recordingUDPConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	return 0, 0, 0, nil, net.ErrClosed
}

func (c *recordingUDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	c.writes = append(c.writes, bytes.Clone(b))
	return len(b), len(oob), nil
}

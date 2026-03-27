package conceal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

func TestMasqueradeConnWriteRecordEncodesPayload(t *testing.T) {
	rules := mustTestRules(t, "<dz be 2><d>")
	raw := &recordingConn{}
	pool := newTestBufferPool()

	conn, ok := NewMasqueradeConn(raw, pool, MasqueradeOpts{RulesOut: rules})
	if !ok {
		t.Fatal("expected masquerade conn")
	}

	payload := []byte{0x01, 0x02, 0x03}
	n, err := conn.WriteRecord(payload)
	if err != nil {
		t.Fatalf("WriteRecord failed: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("WriteRecord n = %d, want %d", n, len(payload))
	}

	want := []byte{0x00, 0x03, 0x01, 0x02, 0x03}
	if !bytes.Equal(raw.writes[0], want) {
		t.Fatalf("WriteRecord bytes = %x, want %x", raw.writes[0], want)
	}
}

func TestMasqueradeUDPConnWriteMsgUDPEncodesPayload(t *testing.T) {
	rules := mustTestRules(t, "<dz be 2><d>")
	raw := &recordingUDPConn{}
	pool := newTestBufferPool()

	conn, ok := NewMasqueradeUDPConn(raw, pool, MasqueradeOpts{RulesOut: rules})
	if !ok {
		t.Fatal("expected masquerade udp conn")
	}

	payload := []byte{0x01, 0x02, 0x03}
	n, oobn, err := conn.WriteMsgUDP(payload, []byte{0xaa}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51820})
	if err != nil {
		t.Fatalf("WriteMsgUDP failed: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("WriteMsgUDP n = %d, want %d", n, len(payload))
	}
	if oobn != 1 {
		t.Fatalf("WriteMsgUDP oobn = %d, want 1", oobn)
	}

	want := []byte{0x00, 0x03, 0x01, 0x02, 0x03}
	if len(raw.writes) != 1 {
		t.Fatalf("write count = %d, want 1", len(raw.writes))
	}
	if !bytes.Equal(raw.writes[0], want) {
		t.Fatalf("WriteMsgUDP bytes = %x, want %x", raw.writes[0], want)
	}
}

func TestMasqueradeBatchConnWriteBatchEncodesEachMessage(t *testing.T) {
	rules := mustTestRules(t, "<dz be 2><d>")
	raw := &recordingBatchConn{}
	pool := newTestBufferPool()

	conn, ok := NewMasqueradeBatchConn(raw, pool, MasqueradeOpts{RulesOut: rules})
	if !ok {
		t.Fatal("expected masquerade batch conn")
	}

	msgs := []ipv4.Message{
		{Buffers: net.Buffers{[]byte{0x01, 0x02}}},
		{Buffers: net.Buffers{[]byte{0x03}}},
	}
	n, err := conn.WriteBatch(msgs, 0)
	if err != nil {
		t.Fatalf("WriteBatch failed: %v", err)
	}
	if n != len(msgs) {
		t.Fatalf("WriteBatch n = %d, want %d", n, len(msgs))
	}
	if len(raw.batches) != 1 {
		t.Fatalf("batch count = %d, want 1", len(raw.batches))
	}

	want := [][]byte{
		{0x00, 0x02, 0x01, 0x02},
		{0x00, 0x01, 0x03},
	}
	for i, got := range raw.batches[0] {
		if !bytes.Equal(got.data, want[i]) {
			t.Fatalf("batch msg %d = %x, want %x", i, got.data, want[i])
		}
	}
}

func TestPreludeBatchConnWriteBatchEmitsPreludeBeforeInitiation(t *testing.T) {
	raw := &recordingBatchConn{}
	pool := newTestBufferPool()
	msgsPool := newTestMsgsPool()
	rules := mustTestRules(t, "<b 0xaabb>")

	conn, ok := NewPreludeBatchConn(raw, raw, pool, msgsPool, nil, PreludeOpts{
		Jc:   1,
		Jmin: 3,
		Jmax: 3,
		RulesArr: [5]Rules{
			rules,
		},
	})
	if !ok {
		t.Fatal("expected prelude batch conn")
	}

	initiation := make([]byte, 8)
	binary.LittleEndian.PutUint32(initiation[:4], WireguardMsgInitiationType)
	msgs := []ipv4.Message{
		{
			Buffers: net.Buffers{initiation},
			OOB:     []byte{0x44},
			Addr:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51820},
		},
	}

	n, err := conn.WriteBatch(msgs, 0)
	if err != nil {
		t.Fatalf("WriteBatch failed: %v", err)
	}
	if n != len(msgs) {
		t.Fatalf("WriteBatch n = %d, want %d", n, len(msgs))
	}
	if len(raw.batches) != 2 {
		t.Fatalf("batch count = %d, want 2", len(raw.batches))
	}

	preludeBatch := raw.batches[0]
	if len(preludeBatch) != 2 {
		t.Fatalf("prelude batch len = %d, want 2", len(preludeBatch))
	}
	if !bytes.Equal(preludeBatch[0].data, []byte{0xaa, 0xbb}) {
		t.Fatalf("prelude decoy = %x, want aabb", preludeBatch[0].data)
	}
	if len(preludeBatch[1].data) != 3 {
		t.Fatalf("junk len = %d, want 3", len(preludeBatch[1].data))
	}
	if !bytes.Equal(raw.batches[1][0].data, initiation) {
		t.Fatalf("main batch payload changed")
	}
}

func mustTestRules(t *testing.T, spec string) Rules {
	t.Helper()

	rules, err := ParseRules(spec)
	if err != nil {
		t.Fatalf("ParseRules(%q): %v", spec, err)
	}
	return rules
}

func newTestBufferPool() *sync.Pool {
	return &sync.Pool{
		New: func() any {
			return make([]byte, 256)
		},
	}
}

func newTestMsgsPool() *sync.Pool {
	return &sync.Pool{
		New: func() any {
			msgs := make([]ipv4.Message, 8)
			for i := range msgs {
				msgs[i].Buffers = make(net.Buffers, 1)
			}
			return &msgs
		},
	}
}

type recordingConn struct {
	writes [][]byte
}

func (c *recordingConn) Read(_ []byte) (int, error) {
	return 0, errors.New("not implemented")
}

func (c *recordingConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}

func (c *recordingConn) Close() error {
	return nil
}

func (c *recordingConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *recordingConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *recordingConn) SetDeadline(time.Time) error {
	return nil
}

func (c *recordingConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *recordingConn) SetWriteDeadline(time.Time) error {
	return nil
}

type recordingUDPConn struct {
	writes [][]byte
}

func (c *recordingUDPConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not implemented")
}

func (c *recordingUDPConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, errors.New("not implemented")
}

func (c *recordingUDPConn) Close() error {
	return nil
}

func (c *recordingUDPConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *recordingUDPConn) SetDeadline(time.Time) error {
	return nil
}

func (c *recordingUDPConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *recordingUDPConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *recordingUDPConn) ReadMsgUDP(_, _ []byte) (int, int, int, *net.UDPAddr, error) {
	return 0, 0, 0, nil, errors.New("not implemented")
}

func (c *recordingUDPConn) WriteMsgUDP(b, _ []byte, _ *net.UDPAddr) (int, int, error) {
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), 1, nil
}

func (c *recordingUDPConn) SyscallConn() (syscall.RawConn, error) {
	return nil, errors.New("not implemented")
}

type recordedBatchMessage struct {
	data []byte
}

type recordingBatchConn struct {
	batches [][]recordedBatchMessage
}

func (c *recordingBatchConn) ReadBatch([]ipv4.Message, int) (int, error) {
	return 0, errors.New("not implemented")
}

func (c *recordingBatchConn) WriteBatch(ms []ipv4.Message, flags int) (int, error) {
	batch := make([]recordedBatchMessage, len(ms))
	for i := range ms {
		batch[i] = recordedBatchMessage{
			data: append([]byte(nil), ms[i].Buffers[0]...),
		}
	}
	c.batches = append(c.batches, batch)
	return len(ms), nil
}

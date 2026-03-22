package conn

import (
	"bytes"
	"encoding/binary"
	"net"
	"slices"
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

func TestBindStreamPipelineOrder(t *testing.T) {
	bind := NewBindStream()
	bind.SetMasqueradeOpts(conceal.MasqueradeOpts{
		RulesOut: mustParseRules(t, "<dz be 2><d>"),
	})
	bind.SetFramedOpts(conceal.FramedOpts{H1: mustHeader(t, "777")})
	bind.SetPreludeOpts(conceal.PreludeOpts{
		RulesArr: [5]conceal.Rules{mustParseRules(t, "<b 0xaabb>")},
	})

	got := bind.streamConcealPipeline().names()
	want := []string{"masquerade", "prelude", "framed"}
	if !slices.Equal(got, want) {
		t.Fatalf("stream pipeline = %v, want %v", got, want)
	}
}

func TestBindStreamPipelineOmitsUnsafePrelude(t *testing.T) {
	bind := NewBindStream()
	bind.SetFramedOpts(conceal.FramedOpts{H1: mustHeader(t, "777")})
	bind.SetPreludeOpts(conceal.PreludeOpts{
		RulesArr: [5]conceal.Rules{mustParseRules(t, "<b 0xaabb>")},
	})

	got := bind.streamConcealPipeline().names()
	want := []string{"framed"}
	if !slices.Equal(got, want) {
		t.Fatalf("stream pipeline without format_out = %v, want %v", got, want)
	}
}

func TestBindStreamTCPPreludeBeforeInitiation(t *testing.T) {
	senderRaw, receiverRaw := net.Pipe()
	defer senderRaw.Close()
	defer receiverRaw.Close()

	bind := NewBindStream()
	bind.SetMasqueradeOpts(conceal.MasqueradeOpts{
		RulesOut: mustParseRules(t, "<dz be 2><d>"),
	})
	bind.SetFramedOpts(conceal.FramedOpts{H1: mustHeader(t, "777")})
	bind.SetPreludeOpts(conceal.PreludeOpts{
		RulesArr: [5]conceal.Rules{mustParseRules(t, "<b 0xaabb>")},
	})

	sender := bind.upgradeConn(senderRaw)
	receiver, ok := conceal.NewMasqueradeConn(receiverRaw, &bind.bufferPool, conceal.MasqueradeOpts{
		RulesIn: mustParseRules(t, "<dz be 2><d>"),
	})
	if !ok {
		t.Fatal("expected masquerade reader")
	}

	initPacket := makeInitiationPacket()
	writeErr := make(chan error, 1)
	go func() {
		_, err := sender.Write(initPacket)
		writeErr <- err
	}()

	prelude := readPacket(t, receiver, 16)
	if !bytes.Equal(prelude, []byte{0xaa, 0xbb}) {
		t.Fatalf("prelude payload = %x, want aabb", prelude)
	}

	gotInit := readPacket(t, receiver, len(initPacket))
	if len(gotInit) != len(initPacket) {
		t.Fatalf("init length = %d, want %d", len(gotInit), len(initPacket))
	}
	if gotHeader := binary.LittleEndian.Uint32(gotInit[:4]); gotHeader != 777 {
		t.Fatalf("init header = %d, want 777", gotHeader)
	}

	if err := <-writeErr; err != nil {
		t.Fatalf("write failed: %v", err)
	}
}

func TestBindStreamTCPPreludeSkipsTransportPackets(t *testing.T) {
	senderRaw, receiverRaw := net.Pipe()
	defer senderRaw.Close()
	defer receiverRaw.Close()

	bind := NewBindStream()
	bind.SetMasqueradeOpts(conceal.MasqueradeOpts{
		RulesOut: mustParseRules(t, "<dz be 2><d>"),
	})
	bind.SetPreludeOpts(conceal.PreludeOpts{
		RulesArr: [5]conceal.Rules{mustParseRules(t, "<b 0xaabb>")},
	})

	sender := bind.upgradeConn(senderRaw)
	receiver, ok := conceal.NewMasqueradeConn(receiverRaw, &bind.bufferPool, conceal.MasqueradeOpts{
		RulesIn: mustParseRules(t, "<dz be 2><d>"),
	})
	if !ok {
		t.Fatal("expected masquerade reader")
	}

	transport := makeTransportPacket()
	writeErr := make(chan error, 1)
	go func() {
		_, err := sender.Write(transport)
		writeErr <- err
	}()

	gotTransport := readPacket(t, receiver, len(transport))
	if !bytes.Equal(gotTransport, transport) {
		t.Fatalf("transport payload changed unexpectedly")
	}

	if err := <-writeErr; err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if err := receiver.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	buf := make([]byte, len(transport))
	if _, err := receiver.Read(buf); err == nil {
		t.Fatal("expected no extra prelude packet for transport write")
	}
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

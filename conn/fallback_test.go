package conn

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conceal"
)

func TestBindStreamFallbackProxiesFormatErrorToTCPPort(t *testing.T) {
	fallbackListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fallback: %v", err)
	}
	defer fallbackListener.Close()

	fallbackPort := fallbackListener.Addr().(*net.TCPAddr).Port
	probe := []byte("GET / HTTP/1.1\r\n")
	response := []byte("HTTP/1.1 200 OK\r\n\r\n")
	received := make(chan []byte, 1)
	served := make(chan error, 1)
	go func() {
		conn, err := fallbackListener.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, len(probe))
		if _, err := io.ReadFull(conn, buf); err != nil {
			served <- err
			return
		}
		received <- bytes.Clone(buf)
		_, err = conn.Write(response)
		served <- err
	}()

	bind := NewBindStream()
	bind.SetMasqueradeOpts(conceal.MasqueradeOpts{
		RulesIn:  mustParseRules(t, "<b 0xfeed><dz be 2><d>"),
		RulesOut: mustParseRules(t, "<b 0xfeed><dz be 2><d>"),
	})
	bind.SetFallbackPort(uint16(fallbackPort))

	listenPort := freeTCPPort(t)
	_, actualPort, err := bind.Open(listenPort)
	if err != nil {
		t.Fatalf("open bind stream: %v", err)
	}
	defer bind.Close()

	client, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(actualPort))))
	if err != nil {
		t.Fatalf("dial bind stream: %v", err)
	}
	defer client.Close()

	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := client.Write(probe[:2]); err != nil {
		t.Fatalf("write initial probe bytes: %v", err)
	}
	if _, err := client.Write(probe[2:]); err != nil {
		t.Fatalf("write remaining probe bytes: %v", err)
	}

	gotResponse := make([]byte, len(response))
	if _, err := io.ReadFull(client, gotResponse); err != nil {
		t.Fatalf("read fallback response: %v", err)
	}
	if !bytes.Equal(gotResponse, response) {
		t.Fatalf("fallback response = %q, want %q", gotResponse, response)
	}

	select {
	case gotProbe := <-received:
		if !bytes.Equal(gotProbe, probe) {
			t.Fatalf("fallback received = %q, want %q", gotProbe, probe)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fallback service did not receive probe")
	}

	if err := <-served; err != nil {
		t.Fatalf("fallback service failed: %v", err)
	}
}

func TestFallbackUDPConnProxiesFormatErrorToUDPPort(t *testing.T) {
	fallbackServer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen fallback udp: %v", err)
	}
	defer fallbackServer.Close()

	probe := []byte("GE")
	response := []byte("udp-ok")
	received := make(chan []byte, 1)
	served := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		n, addr, err := fallbackServer.ReadFromUDP(buf)
		if err != nil {
			served <- err
			return
		}
		received <- bytes.Clone(buf[:n])
		_, err = fallbackServer.WriteToUDP(response, addr)
		served <- err
	}()

	raw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen awg udp: %v", err)
	}
	defer raw.Close()

	pool := sync.Pool{
		New: func() any {
			return make([]byte, 65535)
		},
	}
	masquerade, ok := conceal.NewMasqueradeUDPConn(raw, &pool, conceal.MasqueradeOpts{
		RulesIn: mustParseRules(t, "<b 0xfeed><dz be 2><d>"),
	})
	if !ok {
		t.Fatal("expected masquerade udp conn")
	}
	fallback := newFallbackUDPConn(masquerade, raw, uint16(fallbackServer.LocalAddr().(*net.UDPAddr).Port))

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, _, _, _, err := fallback.ReadMsgUDP(buf, nil)
		readDone <- err
	}()

	client, err := net.DialUDP("udp4", nil, raw.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial awg udp: %v", err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set udp deadline: %v", err)
	}

	if _, err := client.Write(probe); err != nil {
		t.Fatalf("write udp probe: %v", err)
	}

	gotResponse := make([]byte, len(response))
	if _, err := io.ReadFull(client, gotResponse); err != nil {
		t.Fatalf("read udp fallback response: %v", err)
	}
	if !bytes.Equal(gotResponse, response) {
		t.Fatalf("udp fallback response = %q, want %q", gotResponse, response)
	}

	select {
	case gotProbe := <-received:
		if !bytes.Equal(gotProbe, probe) {
			t.Fatalf("udp fallback received = %q, want %q", gotProbe, probe)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("udp fallback service did not receive probe")
	}

	if err := <-served; err != nil {
		t.Fatalf("udp fallback service failed: %v", err)
	}

	raw.Close()
	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("fallback ReadMsgUDP did not exit after close")
	}
}

func freeTCPPort(t *testing.T) uint16 {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate tcp port: %v", err)
	}
	defer listener.Close()

	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

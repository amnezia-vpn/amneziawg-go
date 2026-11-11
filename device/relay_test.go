package device

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20"
)

// openTail decrypts the last n bytes of packet as a relay does.
func openTail(key, packet []byte, n int) []byte {
	cip, _ := chacha20.NewUnauthenticatedCipher(key, packet[:HeaderCipherNonceSize])
	tail := bytes.Clone(packet[len(packet)-n:])
	cip.XORKeyStream(tail, tail)
	return tail
}

func TestRelaySeal(t *testing.T) {
	var nilRelay *Relay
	if nilRelay.TailSize() != 0 || nilRelay.Seal(nil) != nil {
		t.Fatal("nil relay must be no-op")
	}

	relay := &Relay{}
	if relay.set("relay_path", "0102030000000000") != nil {
		t.Fatal("failed to set path")
	}
	if relay.TailSize() != 0 {
		t.Fatal("relay without key must be no-op")
	}
	rand.Read(relay.Key[:])
	if relay.TailSize() != 8 {
		t.Fatalf("tail size = %d, want 8", relay.TailSize())
	}
	clone := *relay
	if clone.set("relay_path", "ff") != nil || relay.TailSize() != 8 || relay.Path()[0] != 1 {
		t.Fatal("copy must not share path with original")
	}
	if fresh := (Relay{Key: relay.Key}); fresh.set("relay_path", "ff") != nil || clone != fresh {
		t.Fatal("set must clear old path bytes")
	}

	packet := make([]byte, 200)
	rand.Read(packet)
	orig := bytes.Clone(packet)
	if err := relay.Seal(packet); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(packet[:192], orig[:192]) {
		t.Fatal("seal modified bytes before tail")
	}

	if tail, want := openTail(relay.Key[:], packet, 8), []byte{1, 2, 3, 0, 0, 0, 0, 0}; !bytes.Equal(tail, want) {
		t.Fatalf("tail = %x, want %x", tail, want)
	}

	if relay.set("relay_path", hex.EncodeToString(make([]byte, 65))) == nil {
		t.Fatal("path out of range must fail")
	}
}

func TestRelayDevicePing(t *testing.T) {
	goroutineLeakCheck(t)
	pair := genTestPair(t, true, "s1", "15", "random_trailers", "true")

	var key [32]byte
	rand.Read(key[:])
	for _, peer := range pair[0].dev.peers.keyMap {
		cfg := uapiCfg(
			"public_key", hex.EncodeToString(peer.handshake.remoteStatic[:]),
			"relay_key", hex.EncodeToString(key[:]),
			"relay_path", "01020304050607080000",
		)
		if err := pair[0].dev.IpcSet(cfg); err != nil {
			t.Fatal(err)
		}
	}

	get, _ := pair[0].dev.IpcGet()
	want := fmt.Sprintf("relay_key=%x\nrelay_path=01020304050607080000\n", key)
	if !strings.Contains(get, want) {
		t.Fatalf("IpcGet does not contain relay config:\n%s", get)
	}
	for _, peer := range pair[0].dev.peers.keyMap {
		cfg := uapiCfg(
			"public_key", hex.EncodeToString(peer.handshake.remoteStatic[:]),
			"relay_key", hex.EncodeToString(make([]byte, 32)),
			"relay_path", "zz",
		)
		if pair[0].dev.IpcSet(cfg) == nil {
			t.Fatal("invalid relay path must fail")
		}
	}
	if get, _ := pair[0].dev.IpcGet(); !strings.Contains(get, want) {
		t.Fatalf("failed set changed relay config:\n%s", get)
	}

	pair.Send(t, Ping, nil)
	pair.Send(t, Pong, nil)

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, peer := range pair[0].dev.peers.keyMap {
		cfg := uapiCfg(
			"random_trailers", "false",
			"public_key", hex.EncodeToString(peer.handshake.remoteStatic[:]),
			"endpoint", conn.LocalAddr().String(),
		)
		if err := pair[0].dev.IpcSet(cfg); err != nil {
			t.Fatal(err)
		}
		peer.handshake.mutex.Lock()
		peer.handshake.lastSentHandshake = time.Time{}
		peer.handshake.mutex.Unlock()
		if err := peer.SendHandshakeInitiation(false); err != nil {
			t.Fatal(err)
		}
	}

	packet := make([]byte, 2048)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	n, err := conn.Read(packet)
	if err != nil {
		t.Fatal(err)
	}
	if n != 15+MessageInitiationSize+10 {
		t.Fatalf("initiation size = %d", n)
	}
	if tail, want := openTail(key[:], packet[:n], 10), []byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0}; !bytes.Equal(tail, want) {
		t.Fatalf("tail = %x, want %x", tail, want)
	}
}

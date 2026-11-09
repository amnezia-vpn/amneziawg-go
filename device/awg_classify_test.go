/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	mrand "math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn/bindtest"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

// wideRangeConfig is an AmneziaWG 3.1 configuration with RandomTrailers,
// S1-S4 that differ and header ranges of 100,000,001 values each (about 2.3%
// of the 32-bit values), with or without header protection. With it, the
// bytes of a transport packet at the offsets of the three handshake messages
// fall in those messages' ranges for about 7% of the packets.
func wideRangeConfig(tb testing.TB, headerProtection bool) []string {
	cfg := []string{
		"s1", "71",
		"s2", "38",
		"s3", "25",
		"s4", "19",
		"h1", "100000000-200000000",
		"h2", "1200000000-1300000000",
		"h3", "2300000000-2400000000",
		"h4", "3400000000-3500000000",
		"random_trailers", "true",
	}
	if headerProtection {
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			tb.Fatal(err)
		}
		cfg = append(cfg, "header_protection_key", hex.EncodeToString(key[:]))
	}
	return cfg
}

func newClassifyTestDevice(tb testing.TB, cfg []string) *Device {
	binds := bindtest.NewChannelBinds()
	dev := NewDevice(tuntest.NewChannelTUN().TUN(), binds[0], NewLogger(LogLevelError, ""))
	tb.Cleanup(dev.Close)
	if err := dev.IpcSet(uapiCfg(cfg...)); err != nil {
		tb.Fatal(err)
	}
	return dev
}

// addTestKeypair registers a keypair under a new receiver index of dev.
func addTestKeypair(tb testing.TB, dev *Device) uint32 {
	index, err := dev.indexTable.NewIndexForHandshake(nil, nil)
	if err != nil {
		tb.Fatal(err)
	}
	dev.indexTable.SwapIndexForKeypair(index, new(Keypair))
	return index
}

// transportDatagram lays out a transport packet as RoutineEncryption does,
// with random bytes for the ciphertext, and returns its S4 random bytes and
// its header (type, receiver and counter, not yet protected).
func transportDatagram(dev *Device, receiver uint32, counter uint64, contentSize int) (datagram, crypt, header []byte) {
	padding := int(dev.paddings.transport.Load())
	datagram = make([]byte, padding+MessageTransportHeaderSize+contentSize)
	crypt = datagram[:padding]
	rand.Read(crypt)
	header = datagram[padding : padding+MessageTransportHeaderSize]
	binary.LittleEndian.PutUint32(header[:4], dev.headers.transport.Load().PickOne())
	binary.LittleEndian.PutUint32(header[4:8], receiver)
	binary.LittleEndian.PutUint64(header[8:16], counter)
	rand.Read(datagram[padding+MessageTransportHeaderSize:])
	return
}

// protectHeaderOnce applies header protection with a single draw, as
// RoutineEncryption did before protectTransportHeader.
func protectHeaderOnce(tb testing.TB, dev *Device, crypt, header []byte) {
	cip, err := dev.HeaderProtectionCipher(crypt[:HeaderCipherNonceSize])
	if err != nil {
		tb.Fatal(err)
	}
	if cip != nil {
		cip.XORKeyStream(header, header)
	}
}

// receiverHeaderMask is the header protection mask a receiver derives from
// datagram; its first four bytes are the typeHash of the classification.
func receiverHeaderMask(tb testing.TB, dev *Device, datagram []byte) []byte {
	var mask [MessageTransportHeaderSize]byte
	cip, err := dev.HeaderProtectionCipher(datagram[:HeaderCipherNonceSize])
	if err != nil {
		tb.Fatal(err)
	}
	if cip != nil {
		cip.XORKeyStream(mask[:], mask[:])
	}
	return mask[:]
}

// randomContentSize is the size of a transport message's content (padded
// plaintext and tag), from a keepalive to a full packet.
func randomContentSize() int {
	return 16 + mrand.IntN(1409)
}

func TestAWGTransportPacketsReadAsTransport(t *testing.T) {
	dev := newClassifyTestDevice(t, wideRangeConfig(t, true))
	receiver := addTestKeypair(t, dev)
	const n = 20000
	firstMatch, misread := 0, 0
	for i := range n {
		datagram, crypt, header := transportDatagram(dev, receiver, uint64(i), randomContentSize())
		protectHeaderOnce(t, dev, crypt, header)
		typeHash := receiverHeaderMask(t, dev, datagram)[:4]
		if _, msgType, _ := dev.DeterminePacketTypeAndPadding(datagram, typeHash); msgType != MessageTransportType {
			firstMatch++
		}
		_, msgType, padding := dev.determinePacketTypeAndPadding(datagram, typeHash)
		if msgType != MessageTransportType || padding != dev.paddings.transport.Load() {
			misread++
		}
	}
	t.Logf("first match took %d of %d transport packets for handshake messages", firstMatch, n)
	// Makes sure the packets under test include the ones a first match misreads.
	if firstMatch == 0 {
		t.Fatal("no transport packet matched a handshake range; the test does not cover the case")
	}
	if misread != 0 {
		t.Errorf("%d of %d transport packets for a keypair of this device were not read as transport", misread, n)
	}
}

func TestAWGHandshakeMessagesKeepTheirType(t *testing.T) {
	dev := newClassifyTestDevice(t, wideRangeConfig(t, true))
	addTestKeypair(t, dev)
	types := []struct {
		msgType uint32
		size    int
		padding uint32
		header  UintRange
	}{
		{MessageInitiationType, MessageInitiationSize, dev.paddings.init.Load(), dev.headers.init.Load()},
		{MessageResponseType, MessageResponseSize, dev.paddings.response.Load(), dev.headers.response.Load()},
		{MessageCookieReplyType, MessageCookieReplySize, dev.paddings.cookie.Load(), dev.headers.cookie.Load()},
	}
	for _, typ := range types {
		for range 5000 {
			padding := int(typ.padding)
			datagram := make([]byte, padding+typ.size+mrand.IntN(1280-padding-typ.size))
			rand.Read(datagram)
			message := datagram[padding : padding+typ.size]
			binary.LittleEndian.PutUint32(message[:4], typ.header.PickOne())
			cip, err := dev.HeaderProtectionCipher(datagram[:HeaderCipherNonceSize])
			if err != nil {
				t.Fatal(err)
			}
			cip.XORKeyStream(message, message)

			typeHash := receiverHeaderMask(t, dev, datagram)[:4]
			wantSize, wantType, wantPadding := dev.DeterminePacketTypeAndPadding(datagram, typeHash)
			size, msgType, gotPadding := dev.determinePacketTypeAndPadding(datagram, typeHash)
			if size != wantSize || msgType != wantType || gotPadding != wantPadding {
				t.Fatalf("message of type %d read as type %d, size %d, padding %d; first match: type %d, size %d, padding %d",
					typ.msgType, msgType, size, gotPadding, wantType, wantSize, wantPadding)
			}
		}
	}
}

func TestAWGTransportHeaderDrawsAvoidHandshakeRanges(t *testing.T) {
	dev := newClassifyTestDevice(t, wideRangeConfig(t, true))
	const n = 20000
	for i := range n {
		receiver, counter := mrand.Uint32(), uint64(i)
		datagram, crypt, header := transportDatagram(dev, receiver, counter, randomContentSize())
		if err := dev.protectTransportHeader(datagram, crypt, header); err != nil {
			t.Fatal(err)
		}
		mask := receiverHeaderMask(t, dev, datagram)
		_, msgType, padding := dev.DeterminePacketTypeAndPadding(datagram, mask[:4])
		if msgType != MessageTransportType {
			t.Fatalf("packet %d is read as type %d by a first-match receiver", i, msgType)
		}
		var plain [MessageTransportHeaderSize]byte
		applyHash(plain[:], datagram[padding:padding+MessageTransportHeaderSize], mask)
		if !dev.headers.transport.Load().Contains(binary.LittleEndian.Uint32(plain[:4])) ||
			binary.LittleEndian.Uint32(plain[4:8]) != receiver ||
			binary.LittleEndian.Uint64(plain[8:16]) != counter {
			t.Fatalf("packet %d: the receiver reads type, receiver and counter %x", i, plain)
		}
	}
}

func TestAWGTransportHeaderDrawsWithoutHeaderProtection(t *testing.T) {
	dev := newClassifyTestDevice(t, wideRangeConfig(t, false))
	const n = 20000
	before, after := 0, 0
	for i := range n {
		receiver, counter := mrand.Uint32(), uint64(i)
		datagram, crypt, header := transportDatagram(dev, receiver, counter, randomContentSize())
		once := bytes.Clone(datagram)
		protectHeaderOnce(t, dev, once[:len(crypt)], once[len(crypt):len(crypt)+MessageTransportHeaderSize])
		if _, msgType, _ := dev.DeterminePacketTypeAndPadding(once, make([]byte, 4)); msgType != MessageTransportType {
			before++
		}
		if err := dev.protectTransportHeader(datagram, crypt, header); err != nil {
			t.Fatal(err)
		}
		_, msgType, padding := dev.DeterminePacketTypeAndPadding(datagram, make([]byte, 4))
		if msgType != MessageTransportType {
			after++
			continue
		}
		plain := datagram[padding : padding+MessageTransportHeaderSize]
		if binary.LittleEndian.Uint32(plain[4:8]) != receiver || binary.LittleEndian.Uint64(plain[8:16]) != counter {
			t.Fatalf("packet %d: the receiver reads receiver and counter %x", i, plain)
		}
	}
	t.Logf("without header protection a first-match receiver misreads %d of %d packets with one draw, %d after the draws", before, n, after)
	if after > before {
		t.Errorf("the draws left more misread packets (%d) than a single draw (%d)", after, before)
	}
}

// udpPacket is an IPv4 UDP packet from src to dst with a payload of size
// bytes that starts with seq.
func udpPacket(src, dst netip.Addr, size int, seq uint32) []byte {
	packet := make([]byte, 28+size)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	s, d := src.As4(), dst.As4()
	copy(packet[12:16], s[:])
	copy(packet[16:20], d[:])
	binary.BigEndian.PutUint16(packet[20:22], 40000)
	binary.BigEndian.PutUint16(packet[22:24], 40000)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+size))
	binary.BigEndian.PutUint32(packet[28:32], seq)
	return packet
}

// warmUp sends packets from one device to the other until one arrives: the
// first packet a device reads from its TUN can still carry the S4 it had
// before the configuration (amneziawg-go#168), and the receiver drops it.
func warmUp(t *testing.T, from, to testPeer) {
	t.Helper()
	for i := range 5 {
		from.tun.Outbound <- udpPacket(from.ip, to.ip, 100, 1<<31+uint32(i))
		select {
		case <-to.tun.Inbound:
			return
		case <-time.After(6 * time.Second):
		}
	}
	t.Fatal("no packet transited")
}

func TestAWGWideRangesWithRandomTrailersTransit(t *testing.T) {
	goroutineLeakCheck(t)
	pair := genTestPair(t, false, wideRangeConfig(t, true)...)
	warmUp(t, pair[1], pair[0])
	warmUp(t, pair[0], pair[1])
	const n = 1000
	for _, direction := range []SendDirection{Ping, Pong} {
		from, to := pair[1], pair[0]
		if direction == Pong {
			from, to = to, from
		}
		lost := 0
		for i := range n {
			packet := udpPacket(from.ip, to.ip, 200+mrand.IntN(1000), uint32(i))
			from.tun.Outbound <- packet
			select {
			case got := <-to.tun.Inbound:
				if !bytes.Equal(got, packet) {
					t.Fatalf("%s %d did not transit correctly", direction, i)
				}
			case <-time.After(time.Second):
				lost++
			}
		}
		if lost != 0 {
			t.Errorf("%s: %d of %d packets lost", direction, lost, n)
		}
	}
}

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"testing"
)

// Header ranges 50,000,000 wide, which is the width AmneziaWG's own client
// config generator emits for H1-H4.
const (
	testRangeWidth = 50_000_000

	testH1Lo = 205127846
	testH2Lo = 592243917
	testH3Lo = 1526611121
	testH4Lo = 1669322812

	testS1 = 49
	testS2 = 57
	testS3 = 37
	testS4 = 27
)

func awgTestDevice(randomTrailers bool) *Device {
	device := new(Device)

	device.paddings.init.Store(testS1)
	device.paddings.response.Store(testS2)
	device.paddings.cookie.Store(testS3)
	device.paddings.transport.Store(testS4)

	var r UintRange
	r.FromUint32(testH1Lo, testH1Lo+testRangeWidth)
	device.headers.init.Store(r)
	r.FromUint32(testH2Lo, testH2Lo+testRangeWidth)
	device.headers.response.Store(r)
	r.FromUint32(testH3Lo, testH3Lo+testRangeWidth)
	device.headers.cookie.Store(r)
	r.FromUint32(testH4Lo, testH4Lo+testRangeWidth)
	device.headers.transport.Store(r)

	device.randomTrailers.Store(randomTrailers)
	return device
}

// A well-formed transport datagram: S4 bytes of crypto padding, a type value
// drawn from H4, then ciphertext-shaped bytes. Deterministic in seed so a
// failure reproduces exactly.
func awgTransportDatagram(seed uint64, payloadLen int) []byte {
	buf := make([]byte, testS4+MessageTransportSize+payloadLen)

	x := seed*6364136223846793005 + 1
	for i := range buf {
		x = x*6364136223846793005 + 1442695040888963407
		buf[i] = byte(x >> 33)
	}

	msgType := uint32(testH4Lo) + uint32(seed%testRangeWidth)
	binary.LittleEndian.PutUint32(buf[testS4:testS4+4], msgType)
	return buf
}

func countMisclassified(t *testing.T, randomTrailers bool, n int) int {
	t.Helper()
	device := awgTestDevice(randomTrailers)
	typeHash := make([]byte, 4) // header protection off

	wrong := 0
	for i := 0; i < n; i++ {
		packet := awgTransportDatagram(uint64(i), 1373)
		_, msgType, padding := device.DeterminePacketTypeAndPadding(packet, typeHash)
		if msgType != MessageTransportType || padding != testS4 {
			wrong++
		}
	}
	return wrong
}

// TestDeterminePacketTypeTransportNotStolenByRelaxedHandshakeSizes guards the
// interaction between random trailers and the handshake size tests.
//
// With RandomTrailers enabled the three handshake size tests relax from `==`
// to `>`, because a trailer makes a handshake message longer than its fixed
// size. That relaxation also makes each of them match a full-size *transport*
// packet, since a transport packet is longer than any handshake message. The
// only thing then standing between a data packet and a handshake misparse is
// the type-range test -- and for a transport packet those four bytes sit in
// ciphertext, so they are uniformly random.
//
// A header range spanning n of the 2^32 values therefore claims n/2^32 of all
// data packets, and the three handshake ranges are tried before transport.
// With the ~50-million-wide ranges the config generator emits that is
// 3 * 1.16% = ~3.5% of every transport packet silently dropped as an
// unparseable handshake, which is enough to collapse a TCP sender (Mathis:
// ~0.35 Mbit/s over a 170 ms path at a 1373-byte MSS).
func TestDeterminePacketTypeTransportNotStolenByRelaxedHandshakeSizes(t *testing.T) {
	const n = 200_000

	if wrong := countMisclassified(t, true, n); wrong != 0 {
		t.Errorf(
			"random trailers on: %d/%d transport packets misclassified as handshakes (%.3f%%)",
			wrong, n, 100*float64(wrong)/float64(n),
		)
	}
}

// The unrelaxed path was never affected by this, and must stay that way.
func TestDeterminePacketTypeTransportExactWithoutRandomTrailers(t *testing.T) {
	const n = 200_000

	if wrong := countMisclassified(t, false, n); wrong != 0 {
		t.Errorf("random trailers off: %d/%d transport packets misclassified", wrong, n)
	}
}

// The three handshake kinds in the exact order DeterminePacketTypeAndPadding
// tries them.
var awgHandshakeKinds = [3]struct {
	name    string
	padding uint32
	msgSize int
	hLo     uint32
	msgType uint32
}{
	{"initiation", testS1, MessageInitiationSize, testH1Lo, MessageInitiationType},
	{"response", testS2, MessageResponseSize, testH2Lo, MessageResponseType},
	{"cookie", testS3, MessageCookieReplySize, testH3Lo, MessageCookieReplyType},
}

// A well-formed handshake datagram: Sk bytes of crypto padding, a type value
// drawn from Hk, the message body, then trailerLen random trailer bytes.
// Deterministic in seed, like awgTransportDatagram.
func awgHandshakeDatagram(seed uint64, kind, trailerLen int) []byte {
	k := awgHandshakeKinds[kind]
	buf := make([]byte, int(k.padding)+k.msgSize+trailerLen)

	x := seed*6364136223846793005 + 1
	for i := range buf {
		x = x*6364136223846793005 + 1442695040888963407
		buf[i] = byte(x >> 33)
	}

	msgType := k.hLo + uint32(seed%testRangeWidth)
	binary.LittleEndian.PutUint32(buf[k.padding:k.padding+4], msgType)
	return buf
}

// awgPrecedingRangeTests counts the type-range tests that run before `kind`'s
// own relaxed test for a datagram of `size` bytes, i.e. the ones that can steal
// it. Each is an independent testRangeWidth/2^32 chance, since the bytes they
// decode are random padding or body bytes rather than this message's type.
func awgPrecedingRangeTests(kind, size int) int {
	n := 1 // the transport test, which any handshake datagram is long enough for

	for j, k := range awgHandshakeKinds {
		exact := int(k.padding) + k.msgSize
		if size == exact && j != kind {
			n++ // an exact test for a different kind, all of which run first
		}
		if j < kind && size > exact {
			n++ // an earlier kind's relaxed test
		}
	}
	return n
}

// TestDeterminePacketTypeHandshakeExactStillClassified pins the guarantee that
// motivates running the exact `==` tests before the transport test: a handshake
// message carrying no trailer is classified deterministically, never stolen.
//
// This is not a corner case. peer.randomTrailer returns 0 whenever udpWindow is
// below the packet size, and udpWindow starts at 0, so the first initiation to
// a fresh peer always has exactly S1+MessageInitiationSize bytes.
func TestDeterminePacketTypeHandshakeExactStillClassified(t *testing.T) {
	const n = 20_000

	for kind, k := range awgHandshakeKinds {
		device := awgTestDevice(true)
		typeHash := make([]byte, 4) // header protection off

		wrong := 0
		for i := 0; i < n; i++ {
			packet := awgHandshakeDatagram(uint64(i), kind, 0)
			msgSize, msgType, padding := device.DeterminePacketTypeAndPadding(packet, typeHash)
			if msgType != k.msgType || padding != k.padding || msgSize != k.msgSize {
				wrong++
			}
		}
		if wrong != 0 {
			t.Errorf("%s without trailer: %d/%d misclassified, want 0", k.name, wrong, n)
		}
	}
}

// TestDeterminePacketTypeHandshakeWithTrailerLossBounded measures the cost of
// the fix rather than the fix itself.
//
// Testing transport before the relaxed handshake tests moves the size/range
// ambiguity off data packets and onto trailer-bearing handshakes: each range
// tried earlier claims testRangeWidth/2^32 of them. That is the trade the
// ordering deliberately makes, and it is fine -- handshakes are rare and
// retried 18 times -- but it should stay at the theoretical collision rate
// instead of drifting into something structural.
func TestDeterminePacketTypeHandshakeWithTrailerLossBounded(t *testing.T) {
	const (
		n = 20_000
		// Statistical slack on top of the theoretical rate. At n=20,000 and
		// p~1-3% the standard error is under 0.13 points, so 1.25x is many
		// sigma away from a false failure while still catching a whole extra
		// range's worth of loss.
		slack = 1.25
	)

	for kind, k := range awgHandshakeKinds {
		device := awgTestDevice(true)
		typeHash := make([]byte, 4) // header protection off

		wrong, tests := 0, 0
		for i := 0; i < n; i++ {
			trailerLen := 1 + i%64
			packet := awgHandshakeDatagram(uint64(i), kind, trailerLen)
			tests += awgPrecedingRangeTests(kind, len(packet))

			msgSize, msgType, padding := device.DeterminePacketTypeAndPadding(packet, typeHash)
			if msgType != k.msgType || padding != k.padding || msgSize != k.msgSize {
				wrong++
			}
		}

		want := float64(tests) / float64(n) * testRangeWidth / (1 << 32)
		got := float64(wrong) / float64(n)
		if got > want*slack {
			t.Errorf(
				"%s with trailer: %d/%d misclassified (%.3f%%), want at most %.3f%% (%.3f%% * %.2f slack)",
				k.name, wrong, n, 100*got, 100*want*slack, 100*want, slack,
			)
		}
	}
}

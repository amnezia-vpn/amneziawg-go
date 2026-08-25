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

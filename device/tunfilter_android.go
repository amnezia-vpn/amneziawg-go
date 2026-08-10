//go:build android

package device

/*
#include <stdbool.h>
#include <stdint.h>

// should be implemented or no-opd by the Android client wrapper
extern bool amneziawg_check_is_tuple_blocked(
    int proto,
    const uint8_t* src_ip,
    int src_ip_len,
    int src_port,
    const uint8_t* dst_ip,
    int dst_ip_len,
    int dst_port
);
*/
import "C"

import (
	"encoding/binary"
	"unsafe"
)

const tunFilterSupported = true

var tunFilterActive = false

func (device *Device) tunFilterConfigure(value string) {
	tunFilterActive = value == "1"
	if tunFilterActive {
		device.tunFilterCache = newTunFilterCache()
	}
}

const (
	tunFilterCacheMaxEntries = 5_000
)

const (
	ipVersion4 = 4
	ipVersion6 = 6

	protoTCP = 6
	protoUDP = 17
)

type tunFilterConnKey struct {
	Proto   uint8
	SrcPort uint16
	DstPort uint16
	SrcIP   [16]byte
	DstIP   [16]byte
}

type tunFilterCacheHolder struct {
	entries map[tunFilterConnKey]bool
	order   [tunFilterCacheMaxEntries]tunFilterConnKey
	head    int
	size    int
}

func newTunFilterCache() tunFilterCacheHolder {
	return tunFilterCacheHolder{
		entries: make(map[tunFilterConnKey]bool, tunFilterCacheMaxEntries),
	}
}

func (c *tunFilterCacheHolder) lookup(key tunFilterConnKey) (blocked bool, ok bool) {
	blocked, ok = c.entries[key]
	return
}

func (c *tunFilterCacheHolder) store(
	key tunFilterConnKey,
	blocked bool,
) {
	if _, exists := c.entries[key]; exists {
		return
	}

	if c.size == tunFilterCacheMaxEntries {
		oldest := c.order[c.head]
		delete(c.entries, oldest)
	} else {
		c.size++
	}

	c.order[c.head] = key
	c.entries[key] = blocked

	c.head++
	if c.head == tunFilterCacheMaxEntries {
		c.head = 0
	}
}

func (c *tunFilterCacheHolder) clear() {
	clear(c.entries)
	c.head = 0
	c.size = 0
}

//

func (device *Device) tunFilterAllows(packet []byte) bool {
	key, ipLen, ok := tunFilterParsePacket(packet)
	if !ok {
		// reject uninspectable traffic
		return false
	}

	if blocked, ok := device.tunFilterCache.lookup(key); ok {
		return !blocked
	}

	blocked := bool(C.amneziawg_check_is_tuple_blocked(
		C.int(key.Proto),

		(*C.uint8_t)(unsafe.Pointer(&key.SrcIP[0])),
		C.int(ipLen),
		C.int(key.SrcPort),

		(*C.uint8_t)(unsafe.Pointer(&key.DstIP[0])),
		C.int(ipLen),
		C.int(key.DstPort),
	))
	device.tunFilterCache.store(key, blocked)

	return !blocked
}

//

func tunFilterParsePacket(
	packet []byte,
) (
	key tunFilterConnKey,
	ipLen int,
	ok bool,
) {
	if len(packet) == 0 {
		return key, 0, false
	}

	switch packet[0] >> 4 {
	case ipVersion4:
		return tunFilterParseIPv4(packet)

	case ipVersion6:
		return tunFilterParseIPv6(packet)

	default:
		return key, 0, false
	}
}

func tunFilterParseIPv4(
	packet []byte,
) (
	key tunFilterConnKey,
	ipLen int,
	ok bool,
) {
	if len(packet) < 20 {
		return key, 0, false
	}

	first := packet[0]

	ihl := int(first&0x0f) * 4
	if ihl < 20 || ihl > len(packet) {
		return key, 0, false
	}

	proto := packet[9]

	switch proto {
	case protoTCP, protoUDP:
		// Supported

	default:
		// ICMP and all other IP protocols are not
		return key, 0, false
	}

	fragment := binary.BigEndian.Uint16(packet[6:8])
	if fragment&0x1fff != 0 || fragment&0x2000 != 0 {
		return key, 0, false
	}

	if len(packet) < ihl+4 {
		return key, 0, false
	}

	key.Proto = proto
	key.SrcPort = binary.BigEndian.Uint16(packet[ihl : ihl+2])
	key.DstPort = binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])

	copy(key.SrcIP[:4], packet[12:16])
	copy(key.DstIP[:4], packet[16:20])

	return key, 4, true
}

func tunFilterParseIPv6(
	packet []byte,
) (
	key tunFilterConnKey,
	ipLen int,
	ok bool,
) {
	if len(packet) < 40 {
		return key, 0, false
	}

	nextHeader := packet[6]
	offset := 40

	for {
		switch nextHeader {
		case protoTCP, protoUDP:
			goto transport

		case 58: // ICMPv6
			return key, 0, false

		case 0, 43, 60:
			// Hop-by-Hop Options, Routing, Destination Options.
			if offset+2 > len(packet) {
				return key, 0, false
			}

			nextHeader = packet[offset]

			extLen := (int(packet[offset+1]) + 1) * 8
			if extLen < 8 || offset+extLen > len(packet) {
				return key, 0, false
			}

			offset += extLen

		case 44:
			// Fragment header.
			//
			// We do not reassemble IPv6 fragments, so the transport tuple
			// cannot be reliably determined.
			return key, 0, false

		case 51:
			// Authentication Header.
			if offset+2 > len(packet) {
				return key, 0, false
			}

			nextHeader = packet[offset]

			// AH length is expressed as 32-bit words minus 2.
			extLen := (int(packet[offset+1]) + 2) * 4
			if extLen < 8 || offset+extLen > len(packet) {
				return key, 0, false
			}

			offset += extLen

		case 50:
			// ESP encrypts the transport header
			return key, 0, false

		default:
			// Unknown extension/next-header type
			return key, 0, false
		}
	}

transport:
	if len(packet) < offset+4 {
		return key, 0, false
	}

	key.Proto = nextHeader
	key.SrcPort = binary.BigEndian.Uint16(packet[offset : offset+2])
	key.DstPort = binary.BigEndian.Uint16(packet[offset+2 : offset+4])

	copy(key.SrcIP[:], packet[8:24])
	copy(key.DstIP[:], packet[24:40])

	return key, 16, true
}

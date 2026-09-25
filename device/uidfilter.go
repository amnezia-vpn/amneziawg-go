/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ReleaseOutboundPacket sends a packet that uidfilter held while its flow was
// being judged (Strict Split Tunneling, issue amnezia-client#2457). It does what
// RoutineReadFromTUN does for a packet it has just read, one packet at a time,
// and is called from a uidfilter worker goroutine.
func (device *Device) ReleaseOutboundPacket(packet []byte) {
	if device.isClosed() {
		return
	}

	var peer *Peer
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < ipv4.HeaderLen {
			return
		}
		peer = device.allowedips.Lookup(packet[IPv4offsetDst : IPv4offsetDst+net.IPv4len])
	case 6:
		if len(packet) < ipv6.HeaderLen {
			return
		}
		peer = device.allowedips.Lookup(packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len])
	}
	if peer == nil || !peer.isRunning.Load() {
		return
	}

	elem := device.NewOutboundElement()
	offset := MessageTransportHeaderSize + int(elem.padding)
	if len(packet) > len(elem.buffer)-offset {
		device.PutMessageBuffer(elem.buffer)
		device.PutOutboundElement(elem)
		return
	}
	elem.packet = elem.buffer[offset : offset+copy(elem.buffer[offset:], packet)]

	elemsForPeer := device.GetOutboundElementsContainer()
	elemsForPeer.elems = append(elemsForPeer.elems, elem)
	peer.StagePackets(elemsForPeer)
	peer.SendStagedPackets()
}

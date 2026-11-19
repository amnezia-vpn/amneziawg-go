//go:build freebsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

// FreeBSD's sticky sockets differ from Linux's in the IPv4 shape only: the
// kernel reports the destination of a received datagram as a bare in_addr
// (IP_RECVDSTADDR) rather than an in_pktinfo, and accepts the same structure
// back to pin the source of an outgoing one (IP_SENDSRCADDR). The two options
// share one value, so a received control message can be resent verbatim,
// which is what ep.src stores. IPv6 uses RFC 3542 in6_pktinfo, same as Linux.
//
// Semantics verified against a live kernel before this port was written; see
// spike/sticky-probe.py in pfSense-pkg-AmneziaWG.

const sizeofInAddr = 4

func (e *StdNetEndpoint) SrcIP() netip.Addr {
	switch len(e.src) {
	case unix.CmsgSpace(sizeofInAddr):
		return netip.AddrFrom4([4]byte(e.src[unix.CmsgLen(0) : unix.CmsgLen(0)+4]))
	case unix.CmsgSpace(unix.SizeofInet6Pktinfo):
		info := (*unix.Inet6Pktinfo)(unsafe.Pointer(&e.src[unix.CmsgLen(0)]))
		// TODO: set zone. in order to do so we need to check if the address is
		// link local, and if it is perform a syscall to turn the ifindex into a
		// zone string because netip uses string zones.
		return netip.AddrFrom16(info.Addr)
	}
	return netip.Addr{}
}

func (e *StdNetEndpoint) SrcIfidx() int32 {
	// IP_RECVDSTADDR carries no interface index. IPV6_PKTINFO does.
	if len(e.src) == unix.CmsgSpace(unix.SizeofInet6Pktinfo) {
		info := (*unix.Inet6Pktinfo)(unsafe.Pointer(&e.src[unix.CmsgLen(0)]))
		return int32(info.Ifindex)
	}
	return 0
}

func (e *StdNetEndpoint) SrcToString() string {
	return e.SrcIP().String()
}

// getSrcFromControl parses the control for IP_RECVDSTADDR/IPV6_PKTINFO and if
// found updates ep with the source information found.
func getSrcFromControl(control []byte, ep *StdNetEndpoint) {
	ep.ClearSrc()

	var (
		hdr  unix.Cmsghdr
		data []byte
		rem  []byte = control
		err  error
	)

	for len(rem) > unix.SizeofCmsghdr {
		hdr, data, rem, err = unix.ParseOneSocketControlMessage(rem)
		if err != nil {
			return
		}

		if hdr.Level == unix.IPPROTO_IP &&
			hdr.Type == unix.IP_RECVDSTADDR {

			if ep.src == nil || cap(ep.src) < unix.CmsgSpace(sizeofInAddr) {
				ep.src = make([]byte, 0, unix.CmsgSpace(sizeofInAddr))
			}
			ep.src = ep.src[:unix.CmsgSpace(sizeofInAddr)]

			hdrBuf := unsafe.Slice((*byte)(unsafe.Pointer(&hdr)), unix.SizeofCmsghdr)
			copy(ep.src, hdrBuf)
			copy(ep.src[unix.CmsgLen(0):], data)
			return
		}

		if hdr.Level == unix.IPPROTO_IPV6 &&
			hdr.Type == unix.IPV6_PKTINFO {

			if ep.src == nil || cap(ep.src) < unix.CmsgSpace(unix.SizeofInet6Pktinfo) {
				ep.src = make([]byte, 0, unix.CmsgSpace(unix.SizeofInet6Pktinfo))
			}

			ep.src = ep.src[:unix.CmsgSpace(unix.SizeofInet6Pktinfo)]

			hdrBuf := unsafe.Slice((*byte)(unsafe.Pointer(&hdr)), unix.SizeofCmsghdr)
			copy(ep.src, hdrBuf)
			copy(ep.src[unix.CmsgLen(0):], data)
			return
		}
	}
}

// setSrcControl appends the stored control message to control. On FreeBSD the
// stored IP_RECVDSTADDR message doubles as IP_SENDSRCADDR (they share a value),
// and IPV6_PKTINFO is symmetric by design. control's len will be set to 0 in
// the event that ep is a default value.
func setSrcControl(control *[]byte, ep *StdNetEndpoint) {
	if cap(*control) < len(ep.src) {
		return
	}
	*control = (*control)[:0]
	*control = append(*control, ep.src...)
}

// stickyControlSize returns the recommended buffer size for pooling sticky
// offloading control data.
var stickyControlSize = unix.CmsgSpace(unix.SizeofInet6Pktinfo)

const StdNetSupportsStickySockets = true

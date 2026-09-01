//go:build freebsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Mirrors sticky_linux_test.go, adjusted for the FreeBSD shapes: IPv4 carries a
// bare in_addr under IP_RECVDSTADDR (no interface index), IPv6 keeps the RFC
// 3542 in6_pktinfo.
//
// Build for the firewall and run it there -- these assert against the kernel's
// own constants and struct layouts, so a host run would prove nothing:
//
//	GOOS=freebsd GOARCH=amd64 go test -c -o sticky.test ./conn/
//	scp sticky.test admin@FIREWALL:/root/ && ssh admin@FIREWALL './sticky.test -test.v'

func setSrc(ep *StdNetEndpoint, addr netip.Addr, ifidx int32) {
	var buf []byte
	if addr.Is4() {
		buf = make([]byte, unix.CmsgSpace(sizeofInAddr))
		hdr := unix.Cmsghdr{
			Level: unix.IPPROTO_IP,
			Type:  unix.IP_RECVDSTADDR,
		}
		hdr.SetLen(unix.CmsgLen(sizeofInAddr))
		copy(buf, unsafe.Slice((*byte)(unsafe.Pointer(&hdr)), int(unsafe.Sizeof(hdr))))

		as4 := addr.As4()
		copy(buf[unix.CmsgLen(0):], as4[:])
	} else {
		buf = make([]byte, unix.CmsgSpace(unix.SizeofInet6Pktinfo))
		hdr := unix.Cmsghdr{
			Level: unix.IPPROTO_IPV6,
			Type:  unix.IPV6_PKTINFO,
		}
		hdr.SetLen(unix.CmsgLen(unix.SizeofInet6Pktinfo))
		copy(buf, unsafe.Slice((*byte)(unsafe.Pointer(&hdr)), int(unsafe.Sizeof(hdr))))

		info := unix.Inet6Pktinfo{
			Ifindex: uint32(ifidx),
			Addr:    addr.As16(),
		}
		copy(buf[unix.CmsgLen(0):], unsafe.Slice((*byte)(unsafe.Pointer(&info)), unix.SizeofInet6Pktinfo))
	}

	ep.src = buf
}

// The reason the whole port is only a few dozen lines: on FreeBSD the option
// that reports a datagram's destination and the one that pins an outgoing
// source are the same number, so a received control message is resent as-is.
func Test_sendAndRecvOptionsMatch(t *testing.T) {
	if unix.IP_SENDSRCADDR != unix.IP_RECVDSTADDR {
		t.Fatalf("IP_SENDSRCADDR (%d) != IP_RECVDSTADDR (%d): the stored cmsg can no longer be resent verbatim",
			unix.IP_SENDSRCADDR, unix.IP_RECVDSTADDR)
	}
}

func Test_setSrcControl(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		ep := &StdNetEndpoint{
			AddrPort: netip.MustParseAddrPort("127.0.0.1:1234"),
		}
		setSrc(ep, netip.MustParseAddr("127.0.0.1"), 0)

		control := make([]byte, stickyControlSize)

		setSrcControl(&control, ep)

		hdr := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
		if hdr.Level != unix.IPPROTO_IP {
			t.Errorf("unexpected level: %d", hdr.Level)
		}
		if hdr.Type != unix.IP_SENDSRCADDR {
			t.Errorf("unexpected type: %d", hdr.Type)
		}
		if uint(hdr.Len) != uint(unix.CmsgLen(sizeofInAddr)) {
			t.Errorf("unexpected length: %d", hdr.Len)
		}
		addr := control[unix.CmsgLen(0) : unix.CmsgLen(0)+4]
		if addr[0] != 127 || addr[1] != 0 || addr[2] != 0 || addr[3] != 1 {
			t.Errorf("unexpected address: %v", addr)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		ep := &StdNetEndpoint{
			AddrPort: netip.MustParseAddrPort("[::1]:1234"),
		}
		setSrc(ep, netip.MustParseAddr("::1"), 5)

		control := make([]byte, stickyControlSize)

		setSrcControl(&control, ep)

		hdr := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
		if hdr.Level != unix.IPPROTO_IPV6 {
			t.Errorf("unexpected level: %d", hdr.Level)
		}
		if hdr.Type != unix.IPV6_PKTINFO {
			t.Errorf("unexpected type: %d", hdr.Type)
		}
		info := (*unix.Inet6Pktinfo)(unsafe.Pointer(&control[unix.CmsgLen(0)]))
		if info.Ifindex != 5 {
			t.Errorf("unexpected ifindex: %d", info.Ifindex)
		}
	})

	t.Run("ClearOnNoSrc", func(t *testing.T) {
		control := make([]byte, stickyControlSize)
		hdr := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
		hdr.Level = 1
		hdr.Type = 2
		hdr.Len = 3

		setSrcControl(&control, &StdNetEndpoint{})

		if len(control) != 0 {
			t.Errorf("unexpected control: %v", control)
		}
	})
}

func Test_getSrcFromControl(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		control := make([]byte, unix.CmsgSpace(sizeofInAddr))
		hdr := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
		hdr.Level = unix.IPPROTO_IP
		hdr.Type = unix.IP_RECVDSTADDR
		hdr.SetLen(unix.CmsgLen(sizeofInAddr))
		copy(control[unix.CmsgLen(0):], []byte{127, 0, 0, 1})

		ep := &StdNetEndpoint{}
		getSrcFromControl(control, ep)

		if ep.SrcIP() != netip.MustParseAddr("127.0.0.1") {
			t.Errorf("unexpected address: %v", ep.SrcIP())
		}
		// IP_RECVDSTADDR carries no ifindex; zero is correct, not a failure.
		if ep.SrcIfidx() != 0 {
			t.Errorf("unexpected ifindex: %d", ep.SrcIfidx())
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		control := make([]byte, unix.CmsgSpace(unix.SizeofInet6Pktinfo))
		hdr := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
		hdr.Level = unix.IPPROTO_IPV6
		hdr.Type = unix.IPV6_PKTINFO
		hdr.SetLen(unix.CmsgLen(unix.SizeofInet6Pktinfo))
		info := (*unix.Inet6Pktinfo)(unsafe.Pointer(&control[unix.CmsgLen(0)]))
		info.Addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		info.Ifindex = 5

		ep := &StdNetEndpoint{}
		getSrcFromControl(control, ep)

		if ep.SrcIP() != netip.MustParseAddr("::1") {
			t.Errorf("unexpected address: %v", ep.SrcIP())
		}
		if ep.SrcIfidx() != 5 {
			t.Errorf("unexpected ifindex: %d", ep.SrcIfidx())
		}
	})

	t.Run("ClearOnEmpty", func(t *testing.T) {
		var control []byte
		ep := &StdNetEndpoint{}
		setSrc(ep, netip.MustParseAddr("::1"), 5)

		getSrcFromControl(control, ep)
		if ep.SrcIP().IsValid() {
			t.Errorf("unexpected address: %v", ep.SrcIP())
		}
		if ep.SrcIfidx() != 0 {
			t.Errorf("unexpected ifindex: %d", ep.SrcIfidx())
		}
	})

	t.Run("Multiple", func(t *testing.T) {
		zeroControl := make([]byte, unix.CmsgSpace(0))
		zeroHdr := (*unix.Cmsghdr)(unsafe.Pointer(&zeroControl[0]))
		zeroHdr.SetLen(unix.CmsgLen(0))

		control := make([]byte, unix.CmsgSpace(sizeofInAddr))
		hdr := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
		hdr.Level = unix.IPPROTO_IP
		hdr.Type = unix.IP_RECVDSTADDR
		hdr.SetLen(unix.CmsgLen(sizeofInAddr))
		copy(control[unix.CmsgLen(0):], []byte{127, 0, 0, 1})

		combined := make([]byte, 0)
		combined = append(combined, zeroControl...)
		combined = append(combined, control...)

		ep := &StdNetEndpoint{}
		getSrcFromControl(combined, ep)

		if ep.SrcIP() != netip.MustParseAddr("127.0.0.1") {
			t.Errorf("unexpected address: %v", ep.SrcIP())
		}
	})
}

// The round trip that matters, against the real kernel: a socket bound to the
// wildcard learns which local address a datagram was sent to, and the reply can
// be pinned back to it. This is the whole mechanism the multi-WAN fix rests on.
func Test_stickyRoundTrip(t *testing.T) {
	// Wildcard, as StdNetBind.Open does. IP_SENDSRCADDR is rejected with
	// EINVAL on a socket already bound to one address -- there is nothing to
	// override there -- so binding 127.0.0.1 here would fail for a reason that
	// has nothing to do with the port.
	sock, err := listenConfig().ListenPacket(context.Background(), "udp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()

	conn := sock.(*net.UDPConn)

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// The wildcard socket's LocalAddr has no address; dial it on loopback.
	srvAddr := &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: conn.LocalAddr().(*net.UDPAddr).Port,
	}

	if _, err := client.WriteToUDP([]byte("probe"), srvAddr); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 128)
	oob := make([]byte, stickyControlSize)

	n, oobn, _, from, err := conn.ReadMsgUDP(buf, oob)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "probe" {
		t.Fatalf("unexpected payload: %q", buf[:n])
	}

	ep := &StdNetEndpoint{AddrPort: from.AddrPort()}
	getSrcFromControl(oob[:oobn], ep)

	// listenConfig() must have enabled IP_RECVDSTADDR for this to be populated;
	// an empty src here means controlfns_freebsd.go never ran.
	if !ep.SrcIP().IsValid() {
		t.Fatal("no source address recovered: IP_RECVDSTADDR was not enabled by listenConfig()")
	}
	if ep.SrcIP() != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("unexpected source: %v", ep.SrcIP())
	}

	var replyOOB []byte = make([]byte, 0, stickyControlSize)
	setSrcControl(&replyOOB, ep)

	if len(replyOOB) == 0 {
		t.Fatal("setSrcControl produced nothing to send")
	}

	if _, _, err := conn.WriteMsgUDP([]byte("reply"), replyOOB, from); err != nil {
		t.Fatalf("sending with a pinned source failed: %v", err)
	}

	rn, replyFrom, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:rn]) != "reply" {
		t.Fatalf("unexpected reply: %q", buf[:rn])
	}
	if !replyFrom.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("reply came from %v", replyFrom.IP)
	}
}

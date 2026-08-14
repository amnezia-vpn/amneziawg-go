//go:build freebsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func init() {
	controlFns = append(controlFns,
		// Attempt to enable reporting of the destination address of incoming
		// datagrams, which is what makes sticky sockets possible: replies can
		// then be pinned to the address the peer actually dialed, instead of
		// whatever source the routing table would pick. Essential on
		// multi-homed systems, where those two differ.
		func(network, address string, c syscall.RawConn) error {
			var err error
			switch network {
			case "udp4":
				c.Control(func(fd uintptr) {
					err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVDSTADDR, 1)
				})
			case "udp6":
				c.Control(func(fd uintptr) {
					err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
				})
			}
			return err
		},
	)
}

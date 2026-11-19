/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

const (
	QueueStagedSize    = 128
	QueueOutboundSize  = 1024
	QueueInboundSize   = 1024
	QueueHandshakeSize = 1024
	MaxSegmentSize     = 2048 - 32 // largest possible UDP datagram
)

// A var instead of a const (like on ios) so embedders can adjust the bound
// to their memory budget before calling NewDevice.
// 0 keeps the default behavior: disable and allow for infinite memory growth.
var PreallocatedBuffersPerPool uint32 = 0

//go:build !android && !ios && !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import "github.com/amnezia-vpn/amneziawg-go/conn"

const (
	QueueStagedSize    = conn.IdealBatchSize
	QueueOutboundSize  = 1024
	QueueInboundSize   = 1024
	QueueHandshakeSize = 1024
	MaxSegmentSize     = (1 << 16) - 1 // largest possible UDP datagram
)

// PreallocatedBuffersPerPool is a var instead of a const (like on ios), so that
// memory-constrained hosts — e.g. consumer routers running the standalone daemon —
// can bound the buffer pools without patching the source. Assign it before calling
// NewDevice (the daemon reads WG_PREALLOCATED_BUFFERS_PER_POOL from the environment).
// 0 keeps the default behavior: disable and allow for infinite memory growth.
var PreallocatedBuffersPerPool uint32 = 0

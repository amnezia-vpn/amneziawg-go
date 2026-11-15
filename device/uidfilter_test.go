/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

// A packet released after uidfilter held it reaches the other side as if it had
// been read from the tun device, handshake included.
func TestReleaseOutboundPacket(t *testing.T) {
	goroutineLeakCheck(t)
	pair := genTestPair(t, true)

	msg := tuntest.Ping(pair[0].ip, pair[1].ip)
	pair[1].dev.ReleaseOutboundPacket(msg)

	select {
	case got := <-pair[0].tun.Inbound:
		if !bytes.Equal(got, msg) {
			t.Error("released packet did not transit correctly")
		}
	case <-time.After(6 * time.Second):
		t.Error("released packet did not transit")
	}
}

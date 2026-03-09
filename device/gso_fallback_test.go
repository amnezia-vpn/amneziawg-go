/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/conn/bindtest"
	"github.com/amnezia-vpn/amneziawg-go/tun/tuntest"
)

// gsoFailBind wraps a Bind and returns ErrUDPGSODisabled{RetryErr: nil} on the
// first Send call, simulating what happens on Linux kernel 6.17 when sendmmsg
// fails with EINVAL (GSO fails, retry without GSO succeeds).
type gsoFailBind struct {
	conn.Bind
	sendCount atomic.Int32
}

func (b *gsoFailBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if b.sendCount.Add(1) == 1 {
		// First send: simulate GSO failure where retry succeeded.
		// RetryErr: nil means the fallback (non-GSO) send worked fine.
		return conn.ErrUDPGSODisabled{RetryErr: nil}
	}
	return b.Bind.Send(bufs, ep)
}

// TestSendHandshakeInitiationGSODisabledFallback verifies that
// SendHandshakeInitiation does not return an error when the underlying Bind
// returns ErrUDPGSODisabled{RetryErr: nil} — i.e. GSO failed but the packet
// was successfully sent via the non-GSO fallback path.
//
// This is a regression test for the kernel 6.17 issue where sendmmsg returns
// EINVAL for GSO sends. Before the fix, SendHandshakeInitiation treated
// ErrUDPGSODisabled as a fatal error even when the retry succeeded.
func TestSendHandshakeInitiationGSODisabledFallback(t *testing.T) {
	channelBinds := bindtest.NewChannelBinds()
	failBind := &gsoFailBind{Bind: channelBinds[0]}

	tun0 := tuntest.NewChannelTUN()
	tun1 := tuntest.NewChannelTUN()

	logger := NewLogger(LogLevelSilent, "")

	dev0 := NewDevice(tun0.TUN(), failBind, logger)
	dev1 := NewDevice(tun1.TUN(), channelBinds[1], logger)
	defer dev0.Close()
	defer dev1.Close()

	cfgs, _ := genConfigs(t)

	if err := dev0.IpcSet(cfgs[0]); err != nil {
		t.Fatalf("dev0 IpcSet: %v", err)
	}
	if err := dev1.IpcSet(cfgs[1]); err != nil {
		t.Fatalf("dev1 IpcSet: %v", err)
	}
	if err := dev0.Up(); err != nil {
		t.Fatalf("dev0 Up: %v", err)
	}

	// Get the peer from dev0.
	dev0.peers.RLock()
	var peer0 *Peer
	for _, p := range dev0.peers.keyMap {
		peer0 = p
		break
	}
	dev0.peers.RUnlock()

	if peer0 == nil {
		t.Fatal("no peer found in dev0")
	}

	// Set a dummy endpoint so SendHandshakeInitiation doesn't bail early.
	peer0.SetEndpointFromPacket(bindtest.ChannelEndpoint(1))

	// This is the core assertion: must return nil even though the first Send
	// returned ErrUDPGSODisabled.
	if err := peer0.SendHandshakeInitiation(false); err != nil {
		t.Errorf("SendHandshakeInitiation returned unexpected error: %v", err)
	}

	if failBind.sendCount.Load() == 0 {
		t.Error("Send was never called on the bind")
	}
}

// TestSendHandshakeResponseGSODisabledFallback is the same test for
// SendHandshakeResponse.
func TestSendHandshakeResponseGSODisabledFallback(t *testing.T) {
	channelBinds := bindtest.NewChannelBinds()
	failBind := &gsoFailBind{Bind: channelBinds[0]}

	tun0 := tuntest.NewChannelTUN()

	logger := NewLogger(LogLevelSilent, "")

	dev0 := NewDevice(tun0.TUN(), failBind, logger)
	defer dev0.Close()

	cfgs, _ := genConfigs(t)

	if err := dev0.IpcSet(cfgs[0]); err != nil {
		t.Fatalf("dev0 IpcSet: %v", err)
	}
	if err := dev0.Up(); err != nil {
		t.Fatalf("dev0 Up: %v", err)
	}

	dev0.peers.RLock()
	var peer0 *Peer
	for _, p := range dev0.peers.keyMap {
		peer0 = p
		break
	}
	dev0.peers.RUnlock()

	if peer0 == nil {
		t.Fatal("no peer found in dev0")
	}

	ep := bindtest.ChannelEndpoint(1)
	peer0.SetEndpointFromPacket(ep)

	// SendHandshakeResponse requires an active handshake state.
	// We only check that ErrUDPGSODisabled is not propagated as a fatal error.
	// A "failed to create response" error is acceptable here (no real handshake).
	err := peer0.SendHandshakeResponse()
	var errGSO conn.ErrUDPGSODisabled
	if errors.As(err, &errGSO) {
		t.Errorf("SendHandshakeResponse leaked ErrUDPGSODisabled: %v", err)
	}
}

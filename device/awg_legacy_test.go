/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"strings"
	"testing"
	"time"
)

// TestUAPILegacyJunkAndItime checks that the restored AmneziaWG 1.5 device keys
// (j1..j3 controlled junk and itime) are accepted by the UAPI set operation,
// stored on the device, and round-tripped by the get operation.
func TestUAPILegacyJunkAndItime(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()

	cfg := strings.Join([]string{
		"i1=<b 0102><r 8>",
		"j1=<b aabb><c>",
		"j2=<r 16>",
		"j3=<t>",
		"itime=42",
		"",
	}, "\n")

	if err := dev.IpcSet(cfg); err != nil {
		t.Fatalf("IpcSet rejected legacy 1.5 keys: %v", err)
	}

	for i, want := range []bool{true, true, true} {
		if dev.jpackets[i] == nil {
			t.Errorf("jpackets[%d] = nil, want set (%v)", i, want)
		}
	}
	if dev.ipackets[0] == nil {
		t.Error("ipackets[0] = nil, want set")
	}

	dev.imitation.mu.Lock()
	gotInterval := dev.imitation.interval
	dev.imitation.mu.Unlock()
	if gotInterval != 42*time.Second {
		t.Errorf("imitation.interval = %v, want 42s", gotInterval)
	}

	got, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	for _, want := range []string{"j1=<b aabb><c>", "j2=<r 16>", "j3=<t>", "itime=42"} {
		if !strings.Contains(got, want) {
			t.Errorf("IpcGet output missing %q\n--- got ---\n%s", want, got)
		}
	}
}

// TestUAPIItimeRejectsInvalid checks itime validation.
func TestUAPIItimeRejectsInvalid(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()

	if err := dev.IpcSet("itime=-1\n"); err == nil {
		t.Error("IpcSet accepted negative itime, want error")
	}
	if err := dev.IpcSet("itime=notanumber\n"); err == nil {
		t.Error("IpcSet accepted non-numeric itime, want error")
	}
}

// TestDueSpecialJunkZeroInterval verifies the AmneziaWG 2.0 behaviour: with a
// zero imitation interval the special junk is due on every initiation, so the
// controlled junk is never selected.
func TestDueSpecialJunkZeroInterval(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()

	for i := 0; i < 5; i++ {
		if !dev.dueSpecialJunk() {
			t.Fatalf("dueSpecialJunk() = false on call %d with zero interval, want always true", i)
		}
	}
}

// TestDueSpecialJunkThrottled verifies the AmneziaWG 1.5 behaviour: with a
// non-zero imitation interval the special junk is due on the first initiation
// and then gated until the interval elapses.
func TestDueSpecialJunkThrottled(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()

	dev.imitation.mu.Lock()
	dev.imitation.interval = time.Hour
	dev.imitation.mu.Unlock()

	if !dev.dueSpecialJunk() {
		t.Fatal("dueSpecialJunk() = false on first call, want true")
	}
	if dev.dueSpecialJunk() {
		t.Fatal("dueSpecialJunk() = true within interval, want false (controlled junk turn)")
	}

	// Force the schedule into the past and confirm the special junk is due again.
	dev.imitation.mu.Lock()
	dev.imitation.nextSend = time.Now().Add(-time.Minute)
	dev.imitation.mu.Unlock()
	if !dev.dueSpecialJunk() {
		t.Fatal("dueSpecialJunk() = false after interval elapsed, want true")
	}
}

// TestCounterObfChain verifies the restored <c> tag parses and emits an 8-byte
// monotonic counter.
func TestCounterObfChain(t *testing.T) {
	chain, err := newObfChain("<c>")
	if err != nil {
		t.Fatalf("newObfChain(<c>): %v", err)
	}
	if got := chain.ObfuscatedLen(0); got != 8 {
		t.Fatalf("ObfuscatedLen(0) = %d, want 8", got)
	}

	buf1 := make([]byte, chain.ObfuscatedLen(0))
	chain.Obfuscate(buf1, nil)
	buf2 := make([]byte, chain.ObfuscatedLen(0))
	chain.Obfuscate(buf2, nil)

	if string(buf1) == string(buf2) {
		t.Errorf("counter produced identical consecutive values: %x", buf1)
	}
}

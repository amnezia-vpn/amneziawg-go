/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"strings"
	"testing"
)

// TestIpcSetJunkSizeOrdering checks that jmin/jmax are validated against each
// other. jmin > jmax used to be accepted, and JunkPackets() would then compute
// max-min as a uint32 underflow and hand the result to make([]byte, ...).
func TestIpcSetJunkSizeOrdering(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()

	if err := dev.IpcSet(uapiCfg("jc", "5", "jmin", "500", "jmax", "1000")); err != nil {
		t.Fatalf("valid junk sizes rejected: %v", err)
	}

	err := dev.IpcSet(uapiCfg("jc", "5", "jmin", "1000", "jmax", "500"))
	if err == nil {
		t.Fatal("jmin > jmax was accepted")
	}
	if !strings.Contains(err.Error(), "jmin") {
		t.Errorf("unhelpful error for jmin > jmax: %v", err)
	}

	// The rejected config must not have been partially applied.
	if min, max := dev.junk.min.Load(), dev.junk.max.Load(); min != 500 || max != 1000 {
		t.Errorf("rejected config leaked into device: jmin=%d jmax=%d, want 500/1000", min, max)
	}

	// jmin == jmax is a legal degenerate range: every junk packet is jmin bytes.
	if err := dev.IpcSet(uapiCfg("jc", "5", "jmin", "700", "jmax", "700")); err != nil {
		t.Fatalf("jmin == jmax rejected: %v", err)
	}
	for _, buf := range dev.JunkPackets() {
		if len(buf) != 700 {
			t.Errorf("junk packet size = %d, want 700", len(buf))
		}
	}
}

// TestIpcSetJunkSizeOrderingIncremental checks that a config raising both
// bounds past the current jmax is accepted regardless of line order, since
// jmin is applied before jmax within the same request.
func TestIpcSetJunkSizeOrderingIncremental(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()

	if err := dev.IpcSet(uapiCfg("jc", "5", "jmin", "50", "jmax", "100")); err != nil {
		t.Fatalf("initial junk sizes rejected: %v", err)
	}
	// jmin=500 transiently exceeds the stored jmax=100.
	if err := dev.IpcSet(uapiCfg("jmin", "500", "jmax", "1000")); err != nil {
		t.Fatalf("raising both bounds rejected: %v", err)
	}
	if min, max := dev.junk.min.Load(), dev.junk.max.Load(); min != 500 || max != 1000 {
		t.Errorf("jmin=%d jmax=%d, want 500/1000", min, max)
	}
}

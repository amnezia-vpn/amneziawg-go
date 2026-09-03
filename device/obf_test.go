/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import "testing"

// TestNewObfChainRejectsNegativeLength checks that a negative N argument is
// refused at parse time. It used to be accepted, and the negative length then
// reached make([]byte, ...) and dst[:N] on the first handshake send.
func TestNewObfChainRejectsNegativeLength(t *testing.T) {
	for _, tag := range []string{"r", "rc", "rd", "dz"} {
		spec := "<" + tag + " -1>"
		if _, err := newObfChain(spec); err == nil {
			t.Errorf("newObfChain(%q) accepted a negative length", spec)
		}
	}
}

func TestNewObfChainLengths(t *testing.T) {
	// Zero stays legal: it contributes nothing to the packet.
	chain, err := newObfChain("<r 0>")
	if err != nil {
		t.Fatalf("newObfChain(\"<r 0>\") = %v", err)
	}
	if got := chain.ObfuscatedLen(0); got != 0 {
		t.Errorf("ObfuscatedLen(0) = %d, want 0", got)
	}

	chain, err = newObfChain("<r 4><rc 6><rd 2>")
	if err != nil {
		t.Fatalf("newObfChain = %v", err)
	}
	if got := chain.ObfuscatedLen(0); got != 12 {
		t.Errorf("ObfuscatedLen(0) = %d, want 12", got)
	}
}

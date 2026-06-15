/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"testing"
)

func TestSalamanderRoundTrip(t *testing.T) {
	device := &Device{}
	for i := range device.obfsPSK {
		device.obfsPSK[i] = byte(i + 1)
	}

	packet := []byte("wireguard packet")
	obfuscated, err := device.salamanderObfuscate(packet)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(packet, obfuscated) {
		t.Fatal("obfuscated packet unexpectedly matches plaintext")
	}
	if len(obfuscated) < salamanderPadMin {
		t.Fatalf("obfuscated packet too short: %d", len(obfuscated))
	}

	deobfuscated, ok := device.salamanderDeobfuscate(obfuscated)
	if !ok {
		t.Fatal("failed to deobfuscate")
	}
	if !bytes.Equal(packet, deobfuscated) {
		t.Fatalf("round trip mismatch: got %x want %x", deobfuscated, packet)
	}
}

func TestSalamanderDisabledReturnsInput(t *testing.T) {
	device := &Device{}
	packet := []byte("wireguard packet")

	obfuscated, err := device.salamanderObfuscate(packet)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(packet, obfuscated) {
		t.Fatal("disabled obfuscation changed packet")
	}

	deobfuscated, ok := device.salamanderDeobfuscate(packet)
	if !ok {
		t.Fatal("disabled deobfuscation failed")
	}
	if !bytes.Equal(packet, deobfuscated) {
		t.Fatal("disabled deobfuscation changed packet")
	}
}

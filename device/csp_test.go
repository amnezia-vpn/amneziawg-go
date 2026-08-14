package device

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
	"unicode"
)

// --- helpers ---

func cpsChain(t *testing.T, spec string, counterGetter func() uint32) *obfChain {
	t.Helper()
	chain, err := newObfChainWithCounter(spec, counterGetter)
	if err != nil {
		t.Fatalf("newObfChainWithCounter(%q) failed: %v", spec, err)
	}
	return chain
}

func obfuscate(t *testing.T, chain *obfChain) []byte {
	t.Helper()
	out := make([]byte, chain.ObfuscatedLen(0))
	chain.Obfuscate(out, nil)
	return out
}

// --- <b 0x...> static bytes ---

func TestCPS_StaticBytes(t *testing.T) {
	chain := cpsChain(t, "<b 0xDEADBEEF>", nil)

	if got := chain.ObfuscatedLen(0); got != 4 {
		t.Fatalf("ObfuscatedLen: got %d, want 4", got)
	}

	out := obfuscate(t, chain)
	want := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if !bytes.Equal(out, want) {
		t.Errorf("Obfuscate: got %x, want %x", out, want)
	}

	// Deobfuscate must succeed for matching bytes
	if !chain.Deobfuscate(nil, out) {
		t.Error("Deobfuscate: unexpected false for correct bytes")
	}

	// Deobfuscate must fail for wrong bytes
	wrong := []byte{0x00, 0x00, 0x00, 0x00}
	if chain.Deobfuscate(nil, wrong) {
		t.Error("Deobfuscate: expected false for wrong bytes")
	}
}

// --- <r N> random bytes ---

func TestCPS_RandomBytes(t *testing.T) {
	chain := cpsChain(t, "<r 8>", nil)

	if got := chain.ObfuscatedLen(0); got != 8 {
		t.Fatalf("ObfuscatedLen: got %d, want 8", got)
	}

	out := obfuscate(t, chain)
	if len(out) != 8 {
		t.Errorf("output length: got %d, want 8", len(out))
	}

	// Two consecutive calls should almost certainly differ
	out2 := obfuscate(t, chain)
	if bytes.Equal(out, out2) {
		t.Log("two random outputs were equal — unlikely but not impossible")
	}
}

// --- <rc N> random chars [a-zA-Z] ---

func TestCPS_RandomChars(t *testing.T) {
	chain := cpsChain(t, "<rc 16>", nil)

	if got := chain.ObfuscatedLen(0); got != 16 {
		t.Fatalf("ObfuscatedLen: got %d, want 16", got)
	}

	out := obfuscate(t, chain)
	for i, b := range out {
		if !unicode.IsLetter(rune(b)) {
			t.Errorf("byte[%d] = %02x is not a letter", i, b)
		}
	}

	// Deobfuscate must succeed (only letters)
	if !chain.Deobfuscate(nil, out) {
		t.Error("Deobfuscate: unexpected false for valid chars")
	}

	// Deobfuscate must fail for non-letter bytes
	invalid := make([]byte, 16)
	// 0x01 is not a letter
	if chain.Deobfuscate(nil, invalid) {
		t.Error("Deobfuscate: expected false for non-letter bytes")
	}
}

// --- <rd N> random digits [0-9] ---

func TestCPS_RandomDigits(t *testing.T) {
	chain := cpsChain(t, "<rd 10>", nil)

	if got := chain.ObfuscatedLen(0); got != 10 {
		t.Fatalf("ObfuscatedLen: got %d, want 10", got)
	}

	out := obfuscate(t, chain)
	for i, b := range out {
		if !unicode.IsDigit(rune(b)) {
			t.Errorf("byte[%d] = %02x (%q) is not a digit", i, b, b)
		}
	}

	// Deobfuscate must succeed for digits
	if !chain.Deobfuscate(nil, out) {
		t.Error("Deobfuscate: unexpected false")
	}

	// Deobfuscate must fail for non-digit bytes
	invalid := make([]byte, 10)
	if chain.Deobfuscate(nil, invalid) {
		t.Error("Deobfuscate: expected false for non-digit bytes")
	}
}

// --- <t> timestamp (4 bytes, current unix time) ---

func TestCPS_Timestamp(t *testing.T) {
	before := uint32(time.Now().Unix())
	chain := cpsChain(t, "<t>", nil)

	if got := chain.ObfuscatedLen(0); got != 4 {
		t.Fatalf("ObfuscatedLen: got %d, want 4", got)
	}

	out := obfuscate(t, chain)
	after := uint32(time.Now().Unix())

	ts := binary.BigEndian.Uint32(out)
	if ts < before || ts > after {
		t.Errorf("timestamp %d out of range [%d, %d]", ts, before, after)
	}
}

// --- <c> packet counter ---

func TestCPS_Counter_Values(t *testing.T) {
	cases := []uint32{0, 1, 42, 0xDEADBEEF, 0xFFFFFFFF}

	for _, want := range cases {
		cv := want
		chain := cpsChain(t, "<c>", func() uint32 { return cv })

		if got := chain.ObfuscatedLen(0); got != 4 {
			t.Fatalf("counter=%d ObfuscatedLen: got %d, want 4", want, got)
		}
		if got := chain.DeobfuscatedLen(0); got != 0 {
			t.Fatalf("counter=%d DeobfuscatedLen: got %d, want 0", want, got)
		}

		out := obfuscate(t, chain)
		got := binary.BigEndian.Uint32(out)
		if got != want {
			t.Errorf("counter=%d: encoded value %d", want, got)
		}

		// Deobfuscate always succeeds (no validation on receive side)
		if !chain.Deobfuscate(nil, out) {
			t.Errorf("counter=%d Deobfuscate: unexpected false", want)
		}
	}
}

func TestCPS_Counter_NilGetterFails(t *testing.T) {
	_, err := newObfChainWithCounter("<c>", nil)
	if err == nil {
		t.Fatal("expected error when counterGetter is nil, got nil")
	}
}

// --- mixed chain ---

func TestCPS_Mixed_BytesCounterBytes(t *testing.T) {
	cv := uint32(999)
	// <b 0xDEAD>(2) + <c>(4) + <b 0xBEEF>(2) = 8 bytes total
	chain := cpsChain(t, "<b 0xDEAD><c><b 0xBEEF>", func() uint32 { return cv })

	if got := chain.ObfuscatedLen(0); got != 8 {
		t.Fatalf("ObfuscatedLen: got %d, want 8", got)
	}

	out := obfuscate(t, chain)

	if out[0] != 0xDE || out[1] != 0xAD {
		t.Errorf("prefix: got %02x%02x, want DEAD", out[0], out[1])
	}

	encoded := binary.BigEndian.Uint32(out[2:6])
	if encoded != cv {
		t.Errorf("counter segment: got %d, want %d", encoded, cv)
	}

	if out[6] != 0xBE || out[7] != 0xEF {
		t.Errorf("suffix: got %02x%02x, want BEEF", out[6], out[7])
	}
}

func TestCPS_Mixed_WithRandom(t *testing.T) {
	cv := uint32(77)
	// <c>(4) + <r 4>(4) + <t>(4) = 12 bytes
	chain := cpsChain(t, "<c><r 4><t>", func() uint32 { return cv })

	if got := chain.ObfuscatedLen(0); got != 12 {
		t.Fatalf("ObfuscatedLen: got %d, want 12", got)
	}

	out := obfuscate(t, chain)

	if got := binary.BigEndian.Uint32(out[0:4]); got != cv {
		t.Errorf("counter: got %d, want %d", got, cv)
	}
	// bytes 4-7 are random — just check length is correct
	if len(out) != 12 {
		t.Errorf("total length: got %d, want 12", len(out))
	}
}

// --- error cases ---

func TestCPS_UnknownTag(t *testing.T) {
	_, err := newObfChain("<unknown>")
	if err == nil {
		t.Fatal("expected error for unknown tag")
	}
}

func TestCPS_MissingClosingBracket(t *testing.T) {
	_, err := newObfChain("<b 0xFF")
	if err == nil {
		t.Fatal("expected error for missing >")
	}
}

func TestCPS_InvalidHexBytes(t *testing.T) {
	_, err := newObfChain("<b 0xZZZZ>")
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestCPS_InvalidRandSize(t *testing.T) {
	_, err := newObfChain("<r abc>")
	if err == nil {
		t.Fatal("expected error for non-integer size")
	}
}

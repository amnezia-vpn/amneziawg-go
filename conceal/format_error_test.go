package conceal

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

func TestMasqueradeConnReadRecordReturnsFormatErrorWithData(t *testing.T) {
	rules, err := ParseRules("<b 0xfeed><dz be 2><d>")
	if err != nil {
		t.Fatalf("parse rules: %v", err)
	}

	pool := sync.Pool{
		New: func() any {
			return make([]byte, 65535)
		},
	}
	conn, ok := NewMasqueradeConn(newBenchmarkStreamConn([]byte("GET /")), &pool, MasqueradeOpts{
		RulesIn: rules,
	})
	if !ok {
		t.Fatal("expected masquerade connection")
	}

	buf := make([]byte, 64)
	n, err := conn.ReadRecord(buf)
	if !errors.Is(err, ErrFormat) {
		t.Fatalf("ReadRecord error = %v, want ErrFormat", err)
	}
	if n != 0 {
		t.Fatalf("ReadRecord n = %d, want 0", n)
	}

	var formatErr *FormatError
	if !errors.As(err, &formatErr) {
		t.Fatalf("ReadRecord error type = %T, want *FormatError", err)
	}
	if !bytes.Equal(formatErr.Data, []byte("GE")) {
		t.Fatalf("format error data = %q, want %q", formatErr.Data, "GE")
	}
}

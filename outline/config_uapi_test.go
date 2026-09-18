package outline

import (
	"context"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn/bindtest"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
	"github.com/goccy/go-yaml"
)

func newConfigTestDevice(t *testing.T) *device.Device {
	t.Helper()
	tun := tuntest.NewChannelTUN()
	<-tun.TUN().Events()
	bind := bindtest.NewChannelBinds()[0]
	dev := device.NewDevice(tun.TUN(), bind, device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	return dev
}

func TestAWG31DeviceRoundTrip(t *testing.T) {
	dev := newConfigTestDevice(t)
	if err := dev.IpcSet(mustGenerateIPC(t, awg31FullYAML)); err != nil {
		t.Fatal(err)
	}
	got, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(got, "\n")
	for _, want := range []string{
		"header_protection_key=" + strings.Repeat("01", 32),
		"content_padding_addition=10-30",
		"rekey_after_time=120",
		"rekey_timeout=5-8",
		"reject_after_time=180-240",
		"keepalive_timeout=10-15",
		"max_handshake_attempts=18",
		"random_trailers=1",
		"disable_cookies=1",
	} {
		if !slices.Contains(lines, want) {
			t.Errorf("core did not retain %s", strings.SplitN(want, "=", 2)[0])
		}
	}
	if !slices.Contains(lines, "public_key=106c4d6228512ca43d9ef74e1398f9699eebb70dedb73252d71c5a2698186072") {
		t.Error("core did not retain the peer")
	}
}

func TestAWG31DisabledRoundTrip(t *testing.T) {
	rangeFields := []string{
		"content_padding_addition",
		"rekey_after_time",
		"rekey_timeout",
		"reject_after_time",
		"keepalive_timeout",
		"max_handshake_attempts",
	}

	t.Run("active then explicitly disabled", func(t *testing.T) {
		dev := newConfigTestDevice(t)
		if err := dev.IpcSet(mustGenerateIPC(t, awg31FullYAML)); err != nil {
			t.Fatal(err)
		}
		disabled := fmt.Sprintf(`private_key: %s
header_protection_key: %s
content_padding_addition: 0-0
rekey_after_time: 0-0
rekey_timeout: 0-0
reject_after_time: 0-0
keepalive_timeout: 0-0
max_handshake_attempts: 0-0
random_trailers: off
disable_cookies: off
`, testPrivateKeyBase64, testZeroKeyBase64)
		if err := dev.IpcSet(mustGenerateIPC(t, disabled)); err != nil {
			t.Fatal(err)
		}
		got, err := dev.IpcGet()
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(got, "\n")
		for _, field := range append([]string{"header_protection_key"}, rangeFields...) {
			if containsIPCField(lines, field) {
				t.Errorf("core retained disabled %s", field)
			}
		}
		for _, want := range []string{"random_trailers=0", "disable_cookies=0"} {
			if !slices.Contains(lines, want) {
				t.Errorf("core did not report %s", want)
			}
		}
	})

	t.Run("legacy defaults", func(t *testing.T) {
		dev := newConfigTestDevice(t)
		if err := dev.IpcSet(mustGenerateIPC(t, "private_key: "+testPrivateKeyBase64+"\n")); err != nil {
			t.Fatal(err)
		}
		got, err := dev.IpcGet()
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(got, "\n")
		for _, field := range append([]string{"header_protection_key"}, rangeFields...) {
			if containsIPCField(lines, field) {
				t.Errorf("legacy config unexpectedly enabled %s", field)
			}
		}
		for _, want := range []string{"random_trailers=0", "disable_cookies=0"} {
			if !slices.Contains(lines, want) {
				t.Errorf("legacy config did not report %s", want)
			}
		}
	})

	t.Run("equal ranges normalize", func(t *testing.T) {
		dev := newConfigTestDevice(t)
		var input strings.Builder
		fmt.Fprintf(&input, "private_key: %s\n", testPrivateKeyBase64)
		for _, field := range rangeFields {
			fmt.Fprintf(&input, "%s: 120-120\n", field)
		}
		if err := dev.IpcSet(mustGenerateIPC(t, input.String())); err != nil {
			t.Fatal(err)
		}
		got, err := dev.IpcGet()
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(got, "\n")
		for _, field := range rangeFields {
			if !slices.Contains(lines, field+"=120") {
				t.Errorf("core did not normalize %s", field)
			}
		}
	})
}

func TestAWG31HeaderPadding(t *testing.T) {
	for target := 0; target < 4; target++ {
		t.Run(fmt.Sprintf("s%d below minimum", target+1), func(t *testing.T) {
			dev := newConfigTestDevice(t)
			paddings := []int{12, 12, 12, 12}
			paddings[target] = 11
			input := fmt.Sprintf(`private_key: %s
s1: %d
s2: %d
s3: %d
s4: %d
header_protection_key: %s
`, testPrivateKeyBase64, paddings[0], paddings[1], paddings[2], paddings[3], testSecondPublicKeyBase64)
			if err := dev.IpcSet(mustGenerateIPC(t, input)); err == nil {
				t.Fatalf("core accepted s%d below the header protection minimum", target+1)
			}
		})
	}

	t.Run("all paddings at minimum", func(t *testing.T) {
		dev := newConfigTestDevice(t)
		input := fmt.Sprintf(`private_key: %s
s1: 12
s2: 12
s3: 12
s4: 12
header_protection_key: %s
`, testPrivateKeyBase64, testSecondPublicKeyBase64)
		if err := dev.IpcSet(mustGenerateIPC(t, input)); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("zero key and paddings", func(t *testing.T) {
		dev := newConfigTestDevice(t)
		input := fmt.Sprintf(`private_key: %s
s1: 0
s2: 0
s3: 0
s4: 0
header_protection_key: %s
`, testPrivateKeyBase64, testZeroKeyBase64)
		if err := dev.IpcSet(mustGenerateIPC(t, input)); err != nil {
			t.Fatal(err)
		}
	})
}

func TestFallbackParserRejectsInvalidAWG31(t *testing.T) {
	tests := []struct {
		name    string
		field   string
		value   string
		errPart string
	}{
		{
			name:    "range",
			field:   "content_padding_addition",
			value:   "65536",
			errPart: "content_padding_addition",
		},
		{
			name:    "header protection key length",
			field:   "header_protection_key",
			value:   base64.StdEncoding.EncodeToString(make([]byte, 31)),
			errPart: "header protection key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := fmt.Sprintf("private_key: %s\n%s: %s\n", testPrivateKeyBase64, tt.field, tt.value)
			var node any
			if err := yaml.Unmarshal([]byte(input), &node); err != nil {
				t.Fatal(err)
			}
			dialer, signature, err := FallbackParser(context.Background(), node)
			if err == nil || !strings.Contains(err.Error(), tt.errPart) {
				t.Fatalf("expected field-specific %s error", tt.field)
			}
			if dialer != nil || signature != "" {
				t.Fatal("invalid config allocated a fallback dialer")
			}
		})
	}
}

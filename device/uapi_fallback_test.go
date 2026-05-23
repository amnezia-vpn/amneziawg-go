package device

import (
	"bytes"
	"strings"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/conn/bindtest"
	"github.com/amnezia-vpn/amneziawg-go/tun/tuntest"
)

func TestDeviceFallbackPortUAPI(t *testing.T) {
	tunDevice := tuntest.NewChannelTUN()
	binds := bindtest.NewChannelBinds()
	device := NewDevice(tunDevice.TUN(), binds[0], NewLogger(LogLevelError, ""))
	defer device.Close()

	if err := device.IpcSet(uapiCfg("fallback_port", "8082")); err != nil {
		t.Fatalf("set fallback_port: %v", err)
	}

	var got bytes.Buffer
	if err := device.IpcGetOperation(&got); err != nil {
		t.Fatalf("get uapi: %v", err)
	}
	if !strings.Contains(got.String(), "fallback_port=8082\n") {
		t.Fatalf("IpcGetOperation output missing fallback_port: %q", got.String())
	}

	for _, value := range []string{"0", "65536"} {
		if err := device.IpcSet(uapiCfg("fallback_port", value)); err == nil {
			t.Fatalf("fallback_port=%s accepted, want error", value)
		}
	}
}

func TestDevicePreludeResendIntervalUAPI(t *testing.T) {
	tunDevice := tuntest.NewChannelTUN()
	binds := bindtest.NewChannelBinds()
	device := NewDevice(tunDevice.TUN(), binds[0], NewLogger(LogLevelError, ""))
	defer device.Close()

	var got bytes.Buffer
	if err := device.IpcGetOperation(&got); err != nil {
		t.Fatalf("get default uapi: %v", err)
	}
	if !strings.Contains(got.String(), "prelude_resend_interval=120\n") {
		t.Fatalf("IpcGetOperation output missing default prelude_resend_interval: %q", got.String())
	}

	if err := device.IpcSet(uapiCfg("prelude_resend_interval", "0")); err != nil {
		t.Fatalf("set prelude_resend_interval=0: %v", err)
	}

	got.Reset()
	if err := device.IpcGetOperation(&got); err != nil {
		t.Fatalf("get updated uapi: %v", err)
	}
	if !strings.Contains(got.String(), "prelude_resend_interval=0\n") {
		t.Fatalf("IpcGetOperation output missing disabled prelude_resend_interval: %q", got.String())
	}

	for _, value := range []string{"-1", "abc"} {
		if err := device.IpcSet(uapiCfg("prelude_resend_interval", value)); err == nil {
			t.Fatalf("prelude_resend_interval=%s accepted, want error", value)
		}
	}
}

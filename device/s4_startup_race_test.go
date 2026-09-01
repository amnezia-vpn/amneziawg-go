/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

type gatedTUN struct {
	tun.Device
	readStarted chan struct{}
	release     <-chan struct{}
	once        sync.Once
}

func (tun *gatedTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	tun.once.Do(func() { close(tun.readStarted) })
	<-tun.release
	return tun.Device.Read(bufs, sizes, offset)
}

func configureDevice(t *testing.T, device *Device, config string) {
	t.Helper()
	if err := device.IpcSet(config); err != nil {
		t.Fatal(err)
	}
}

func TestTransportPaddingChangeDuringTUNRead(t *testing.T) {
	const transportPadding = "25"

	configs, endpointConfigs := genConfigs(t, "s4", transportPadding)
	rawTUN0 := tuntest.NewChannelTUN()
	rawTUN1 := tuntest.NewChannelTUN()
	releaseRead := make(chan struct{})
	gated := &gatedTUN{
		Device:      rawTUN0.TUN(),
		readStarted: make(chan struct{}),
		release:     releaseRead,
	}

	pair := testPair{
		{
			tun: rawTUN0,
			ip:  netip.AddrFrom4([4]byte{1, 0, 0, 1}),
			dev: NewDevice(gated, conn.NewDefaultBind(), NewLogger(LogLevelError, "dev0: ")),
		},
		{
			tun: rawTUN1,
			ip:  netip.AddrFrom4([4]byte{1, 0, 0, 2}),
			dev: NewDevice(rawTUN1.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, "dev1: ")),
		},
	}
	for i := range pair {
		t.Cleanup(pair[i].dev.Close)
	}

	select {
	case <-gated.readStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the first TUN read")
	}

	configureDevice(t, pair[0].dev, configs[0])
	configureDevice(t, pair[1].dev, configs[1])

	// Consume the second device's initial pre-configuration read. Its next
	// read then snapshots the configured S4 before the test traffic arrives.
	select {
	case rawTUN1.Outbound <- []byte{0}:
	case <-time.After(time.Second):
		t.Fatal("timed out flushing the second device TUN read")
	}

	for i := range pair {
		endpointConfigs[i^1] = fmt.Sprintf(endpointConfigs[i^1], pair[i].dev.net.port)
	}
	for i := range pair {
		configureDevice(t, pair[i].dev, endpointConfigs[i])
	}

	close(releaseRead)
	pair.Send(t, Ping, nil)
	pair.Send(t, Pong, nil)
}

func TestPaddingBounds(t *testing.T) {
	cases := []struct {
		name    string
		padding int
		valid   bool
	}{
		{name: "zero", padding: 0, valid: true},
		{name: "AWG profile", padding: 25, valid: true},
		{name: "maximum valid", padding: MaxMessageSize - MessageTransportHeaderSize - 1, valid: true},
		{name: "exhausts buffer", padding: MaxMessageSize - MessageTransportHeaderSize, valid: false},
		{name: "uint16 maximum", padding: 1<<16 - 1, valid: false},
	}
	for _, key := range []string{"s1", "s2", "s3", "s4"} {
		for _, tt := range cases {
			t.Run(key+"/"+tt.name, func(t *testing.T) {
				rawTUN := tuntest.NewChannelTUN()
				device := NewDevice(rawTUN.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, "device: "))
				t.Cleanup(device.Close)

				config := fmt.Sprintf("%s=%d\n", key, tt.padding)
				beforeHeader := device.headers.transport.Load()
				if !tt.valid {
					config = fmt.Sprintf("h4=123456\n%s=%d\n", key, tt.padding)
				}
				err := device.IpcSet(config)
				if tt.valid && err != nil {
					t.Fatalf("%s=%d rejected: %v", key, tt.padding, err)
				}
				if !tt.valid && err == nil {
					t.Fatalf("%s=%d accepted", key, tt.padding)
				}
				if !tt.valid && device.headers.transport.Load() != beforeHeader {
					t.Fatalf("%s=%d partially updated the transport header", key, tt.padding)
				}
			})
		}
	}
}

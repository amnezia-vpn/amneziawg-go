/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

// readProbeTUN records the offset RoutineReadFromTUN asked for on its first
// Read and closes `entered` before delegating, so a test can wait until the
// routine has provably captured its S4 padding and parked in the read.
type readProbeTUN struct {
	tun.Device

	once        sync.Once
	entered     chan struct{}
	firstOffset int // written before entered is closed, read after
}

func (t *readProbeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	t.once.Do(func() {
		t.firstOffset = offset
		close(t.entered)
	})
	return t.Device.Read(bufs, sizes, offset)
}

// TestTransportPaddingAppliedWhenConfiguredAfterStartup pins the fix for a
// packet loss that only ever hit the first packet an interface sent.
//
// RoutineReadFromTUN is started by NewDevice, before IpcSet has applied any
// interface config. It has to choose a read offset before it can read, so it
// loads S4 and then blocks in tun.Read -- capturing, on that first pass, the
// default S4 of 0 rather than the configured one. RoutineEncryption writes the
// transport header at buffer[padding:padding+MessageTransportHeaderSize] and
// needs the payload directly after it, so the datagram went out with its type
// field at offset 0 while the peer looks for it at offset S4. The peer decoded
// ciphertext there, matched no header range, and dropped the packet as unknown.
//
// The same window applies to any later `s4` change over UAPI, which used to
// take effect one batch of packets late.
//
// This test makes that race deterministic: it waits for both TUN readers to
// enter Read with S4 still unset, and only then applies the AWG parameters. It
// fails by timing out against the unfixed RoutineReadFromTUN.
func TestTransportPaddingAppliedWhenConfiguredAfterStartup(t *testing.T) {
	goroutineLeakCheck(t)

	const awgS4 = 25

	// Deliberately no S1-S4/H1-H4 here: the devices start with S4 = 0, which is
	// what the TUN readers will capture.
	cfg, endpointCfg := genConfigs(t)

	awgCfg := uapiCfg(
		"jc", "5",
		"jmin", "500",
		"jmax", "1000",
		"s1", "15",
		"s2", "18",
		"s3", "20",
		"s4", strconv.Itoa(awgS4),
		"h1", "123456-123500",
		"h2", "67543-67550",
		"h3", "123123-123200",
		"h4", "32345-32350",
	)

	var (
		tuns   [2]*tuntest.ChannelTUN
		probes [2]*readProbeTUN
		devs   [2]*Device
		ips    [2]netip.Addr
	)
	binds := [2]conn.Bind{conn.NewDefaultBind(), conn.NewDefaultBind()}

	for i := range devs {
		tuns[i] = tuntest.NewChannelTUN()
		probes[i] = &readProbeTUN{Device: tuns[i].TUN(), entered: make(chan struct{})}
		ips[i] = netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)})

		devs[i] = NewDevice(probes[i], binds[i], NewLogger(LogLevelError, fmt.Sprintf("dev%d: ", i)))
		// Registered before the first thing that can fail, so a device already
		// built is still closed if a later one aborts the test.
		t.Cleanup(devs[i].Close)

		if err := devs[i].IpcSet(cfg[i]); err != nil {
			t.Fatalf("failed to configure device %d: %v", i, err)
		}
		if err := devs[i].Up(); err != nil {
			t.Fatalf("failed to bring up device %d: %v", i, err)
		}
		endpointCfg[i^1] = fmt.Sprintf(endpointCfg[i^1], devs[i].net.port)
	}
	for i := range devs {
		if err := devs[i].IpcSet(endpointCfg[i]); err != nil {
			t.Fatalf("failed to configure device endpoint %d: %v", i, err)
		}
	}

	// Both readers are now parked in Read, holding an offset they computed
	// while S4 was still 0. Everything they emit from here on has to pick up
	// the configuration applied below instead.
	for i := range probes {
		<-probes[i].entered
		if got, want := probes[i].firstOffset, MessageTransportHeaderSize; got != want {
			t.Fatalf(
				"dev%d: first read offset %d, want %d -- test cannot exercise the race unless S4 is still unset here",
				i, got, want,
			)
		}
	}

	for i := range devs {
		if err := devs[i].IpcSet(awgCfg); err != nil {
			t.Fatalf("failed to apply AWG config to device %d: %v", i, err)
		}
	}

	// dev1 -> dev0, the first packet either interface has ever sent.
	msg := tuntest.Ping(ips[0], ips[1])
	tuns[1].Outbound <- msg

	select {
	case got := <-tuns[0].Inbound:
		if !bytes.Equal(msg, got) {
			t.Errorf("ping did not transit correctly: got %d bytes, want %d", len(got), len(msg))
		}
	case <-time.After(6 * time.Second):
		t.Fatalf(
			"ping did not transit: it was sent with the S4 padding captured before s4=%d was applied, "+
				"putting the transport type field at offset %d where the peer does not look for it",
			awgS4, 0,
		)
	}
}

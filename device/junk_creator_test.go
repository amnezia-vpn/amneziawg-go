package device

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/conn/bindtest"
	"github.com/amnezia-vpn/amneziawg-go/tun/tuntest"
)

func setUpJunkCreator(t *testing.T) (junkCreator, error) {
	cfg, _ := genASecurityConfigs(t)
	tun := tuntest.NewChannelTUN()
	binds := bindtest.NewChannelBinds()
	level := LogLevelVerbose
	dev := NewDevice(
		tun.TUN(),
		binds[0],
		NewLogger(level, ""),
	)

	if err := dev.IpcSet(cfg[0]); err != nil {
		t.Errorf("failed to configure device %v", err)
		dev.Close()
		return junkCreator{}, err
	}

	jc, err := NewJunkCreator(dev)

	if err != nil {
		t.Errorf("failed to create junk creator %v", err)
		dev.Close()
		return junkCreator{}, err
	}

	return jc, nil
}

func Test_junkCreator_createJunkPackets(t *testing.T) {
	jc, err := setUpJunkCreator(t)
	if err != nil {
		return
	}
	t.Run("", func(t *testing.T) {
		got, err := jc.createJunkPackets(nil)
		if err != nil {
			t.Errorf(
				"junkCreator.createJunkPackets() = %v; failed",
				err,
			)
			return
		}
		seen := make(map[string]bool)
		for _, junk := range got {
			key := string(junk)
			if seen[key] {
				t.Errorf(
					"junkCreator.createJunkPackets() = %v, duplicate key: %v",
					got,
					junk,
				)
				return
			}
			seen[key] = true
		}
	})
}

func Test_junkCreator_randomJunkWithSize(t *testing.T) {
	t.Run("", func(t *testing.T) {
		jc, err := setUpJunkCreator(t)
		if err != nil {
			return
		}
		r1, _ := jc.randomJunkWithSize(10)
		r2, _ := jc.randomJunkWithSize(10)
		fmt.Printf("%v\n%v\n", r1, r2)
		if bytes.Equal(r1, r2) {
			t.Errorf("same junks %v", err)
			jc.device.Close()
			return
		}
	})
}

func Test_junkCreator_randomPacketSize(t *testing.T) {
	jc, err := setUpJunkCreator(t)
	if err != nil {
		return
	}
	for range [30]struct{}{} {
		t.Run("", func(t *testing.T) {
			if got := jc.randomPacketSize(); jc.device.awg.aSecCfg.junkPacketMinSize > got ||
				got > jc.device.awg.aSecCfg.junkPacketMaxSize {
				t.Errorf(
					"junkCreator.randomPacketSize() = %v, not between range [%v,%v]",
					got,
					jc.device.awg.aSecCfg.junkPacketMinSize,
					jc.device.awg.aSecCfg.junkPacketMaxSize,
				)
			}
		})
	}
}

func Test_junkCreator_appendJunk(t *testing.T) {
	jc, err := setUpJunkCreator(t)
	if err != nil {
		return
	}
	t.Run("", func(t *testing.T) {
		s := "apple"
		buffer := bytes.NewBuffer([]byte(s))
		err := jc.appendJunk(buffer, 30)
		if err != nil &&
			buffer.Len() != len(s)+30 {
			t.Errorf("appendWithJunk() size don't match")
		}
		read := make([]byte, 50)
		buffer.Read(read)
		fmt.Println(string(read))
	})
}

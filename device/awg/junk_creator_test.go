package awg

import (
	"bytes"
	"fmt"
	"testing"
)

func setUpJunkCreator(t *testing.T) (junkCreator, error) {
	jc, err := NewJunkCreator(aSecCfgType{
		IsSet:                      true,
		JunkPacketCount:            5,
		JunkPacketMinSize:          500,
		JunkPacketMaxSize:          1000,
		InitHeaderJunkSize:         30,
		ResponseHeaderJunkSize:     40,
		InitPacketMagicHeader:      123456,
		ResponsePacketMagicHeader:  67543,
		UnderloadPacketMagicHeader: 32345,
		TransportPacketMagicHeader: 123123,
	})

	if err != nil {
		t.Errorf("failed to create junk creator %v", err)
		return junkCreator{}, err
	}

	return jc, nil
}

func Test_junkCreator_createJunkPackets(t *testing.T) {
	jc, err := setUpJunkCreator(t)
	if err != nil {
		return
	}
	t.Run("valid", func(t *testing.T) {
		got := make([][]byte, 0, jc.aSecCfg.JunkPacketCount)
		err := jc.CreateJunkPackets(&got)
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
	t.Run("valid", func(t *testing.T) {
		jc, err := setUpJunkCreator(t)
		if err != nil {
			return
		}
		r1, _ := jc.randomJunkWithSize(10)
		r2, _ := jc.randomJunkWithSize(10)
		fmt.Printf("%v\n%v\n", r1, r2)
		if bytes.Equal(r1, r2) {
			t.Errorf("same junks %v", err)
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
		t.Run("valid", func(t *testing.T) {
			if got := jc.randomPacketSize(); jc.aSecCfg.JunkPacketMinSize > got ||
				got > jc.aSecCfg.JunkPacketMaxSize {
				t.Errorf(
					"junkCreator.randomPacketSize() = %v, not between range [%v,%v]",
					got,
					jc.aSecCfg.JunkPacketMinSize,
					jc.aSecCfg.JunkPacketMaxSize,
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
	t.Run("valid", func(t *testing.T) {
		s := "apple"
		buffer := bytes.NewBuffer([]byte(s))
		err := jc.AppendJunk(buffer, 30)
		if err != nil &&
			buffer.Len() != len(s)+30 {
			t.Error("appendWithJunk() size don't match")
		}
		read := make([]byte, 50)
		buffer.Read(read)
		fmt.Println(string(read))
	})
}

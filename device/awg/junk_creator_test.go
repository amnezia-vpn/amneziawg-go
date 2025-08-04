package awg

import (
	"bytes"
	"fmt"
	"testing"
)

func setUpJunkCreator() JunkCreator {
	mh, _ := NewMagicHeaders(
		[]MagicHeader{
			NewMagicHeaderSameValue(123456),
			NewMagicHeaderSameValue(67543),
			NewMagicHeaderSameValue(32345),
			NewMagicHeaderSameValue(123123),
		},
	)

	jc := NewJunkCreator(Cfg{
		IsSet:                  true,
		JunkPacketCount:        5,
		JunkPacketMinSize:      500,
		JunkPacketMaxSize:      1000,
		InitHeaderJunkSize:     30,
		ResponseHeaderJunkSize: 40,
		MagicHeaders:           mh,
	})

	return jc
}

func Test_junkCreator_createJunkPackets(t *testing.T) {
	jc := setUpJunkCreator()
	t.Run("valid", func(t *testing.T) {
		got := make([][]byte, 0, jc.cfg.JunkPacketCount)
		jc.CreateJunkPackets(&got)
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
		jc := setUpJunkCreator()
		r1 := jc.randomJunkWithSize(10)
		r2 := jc.randomJunkWithSize(10)
		fmt.Printf("%v\n%v\n", r1, r2)
		if bytes.Equal(r1, r2) {
			t.Errorf("same junks")
			return
		}
	})
}

func Test_junkCreator_randomPacketSize(t *testing.T) {
	jc := setUpJunkCreator()
	for range [30]struct{}{} {
		t.Run("valid", func(t *testing.T) {
			if got := jc.randomPacketSize(); jc.cfg.JunkPacketMinSize > got ||
				got > jc.cfg.JunkPacketMaxSize {
				t.Errorf(
					"junkCreator.randomPacketSize() = %v, not between range [%v,%v]",
					got,
					jc.cfg.JunkPacketMinSize,
					jc.cfg.JunkPacketMaxSize,
				)
			}
		})
	}
}

func Test_junkCreator_appendJunk(t *testing.T) {
	jc := setUpJunkCreator()
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

package awg

import (
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	v2 "math/rand/v2"
	// "go.uber.org/atomic"
)

type Generator interface {
	Generate() []byte
	Size() int
}

type newGenerator func(string) (Generator, error)

type BytesGenerator struct {
	value []byte
	size  int
}

func (bg *BytesGenerator) Generate() []byte {
	return bg.value
}

func (bg *BytesGenerator) Size() int {
	return bg.size
}

func newBytesGenerator(param string) (Generator, error) {
	hasPrefix := strings.HasPrefix(param, "0x") || strings.HasPrefix(param, "0X")
	if !hasPrefix {
		return nil, fmt.Errorf("not correct hex: %s", param)
	}

	hex, err := hexToBytes(param)
	if err != nil {
		return nil, fmt.Errorf("hexToBytes: %w", err)
	}

	return &BytesGenerator{value: hex, size: len(hex)}, nil
}

func hexToBytes(hexStr string) ([]byte, error) {
	hexStr = strings.TrimPrefix(hexStr, "0x")
	hexStr = strings.TrimPrefix(hexStr, "0X")

	// Ensure even length (pad with leading zero if needed)
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}

	return hex.DecodeString(hexStr)
}

type RandomPacketGenerator struct {
	cha8Rand *v2.ChaCha8
	size     int
}

func (rpg *RandomPacketGenerator) Generate() []byte {
	junk := make([]byte, rpg.size)
	rpg.cha8Rand.Read(junk)
	return junk
}

func (rpg *RandomPacketGenerator) Size() int {
	return rpg.size
}

func newRandomPacketGenerator(param string) (Generator, error) {
	size, err := strconv.Atoi(param)
	if err != nil {
		return nil, fmt.Errorf("random packet parse int: %w", err)
	}

	if size > 1000 {
		return nil, fmt.Errorf("random packet size must be less than 1000")
	}

	buf := make([]byte, 32)
	_, err = crand.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("random packet crand read: %w", err)
	}

	return &RandomPacketGenerator{
		cha8Rand: v2.NewChaCha8([32]byte(buf)),
		size:     size,
	}, nil
}

type TimestampGenerator struct {
}

func (tg *TimestampGenerator) Generate() []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(time.Now().Unix()))
	return buf
}

func (tg *TimestampGenerator) Size() int {
	return 8
}

func newTimestampGenerator(param string) (Generator, error) {
	if len(param) != 0 {
		return nil, fmt.Errorf("timestamp param needs to be empty: %s", param)
	}

	return &TimestampGenerator{}, nil
}

type WaitTimeoutGenerator struct {
	waitTimeout time.Duration
}

func (wtg *WaitTimeoutGenerator) Generate() []byte {
	time.Sleep(wtg.waitTimeout)
	return []byte{}
}

func (wtg *WaitTimeoutGenerator) Size() int {
	return 0
}

func newWaitTimeoutGenerator(param string) (Generator, error) {
	timeout, err := strconv.Atoi(param)
	if err != nil {
		return nil, fmt.Errorf("timeout parse int: %w", err)
	}

	if timeout > 5000 {
		return nil, fmt.Errorf("timeout must be less than 5000ms")
	}

	return &WaitTimeoutGenerator{
		waitTimeout: time.Duration(timeout) * time.Millisecond,
	}, nil
}

type PacketCounterGenerator struct {
}

func (c *PacketCounterGenerator) Generate() []byte {
	buf := make([]byte, 8)
	// TODO: better way to handle counter tag
	binary.BigEndian.PutUint64(buf, PacketCounter.Load())
	return buf
}

func (c *PacketCounterGenerator) Size() int {
	return 8
}

func newPacketCounterGenerator(param string) (Generator, error) {
	if len(param) != 0 {
		return nil, fmt.Errorf("packet counter param needs to be empty: %s", param)
	}

	return &PacketCounterGenerator{}, nil
}

type WaitResponseGenerator struct {
}

func (c *WaitResponseGenerator) Generate() []byte {
	WaitResponse.ShouldWait.Set()
	<-WaitResponse.Channel
	WaitResponse.ShouldWait.UnSet()
	return []byte{}
}

func (c *WaitResponseGenerator) Size() int {
	return 0
}

func newWaitResponseGenerator(param string) (Generator, error) {
	if len(param) != 0 {
		return nil, fmt.Errorf("wait response param needs to be empty: %s", param)
	}

	return &WaitResponseGenerator{}, nil
}

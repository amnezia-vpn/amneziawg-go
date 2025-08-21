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

type randomGeneratorBase struct {
	cha8Rand *v2.ChaCha8
	size     int
}

func newRandomGeneratorBase(param string) (*randomGeneratorBase, error) {
	size, err := strconv.Atoi(param)
	if err != nil {
		return nil, fmt.Errorf("parse int: %w", err)
	}

	if size > 1000 {
		return nil, fmt.Errorf("size must be less than 1000")
	}

	buf := make([]byte, 32)
	_, err = crand.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("crand read: %w", err)
	}

	return &randomGeneratorBase{
		cha8Rand: v2.NewChaCha8([32]byte(buf)),
		size:     size,
	}, nil
}

func (rpg *randomGeneratorBase) generate() []byte {
	junk := make([]byte, rpg.size)
	rpg.cha8Rand.Read(junk)
	return junk
}

func (rpg *randomGeneratorBase) Size() int {
	return rpg.size
}

type RandomBytesGenerator struct {
	*randomGeneratorBase
}

func newRandomBytesGenerator(param string) (Generator, error) {
	rpgBase, err := newRandomGeneratorBase(param)
	if err != nil {
		return nil, fmt.Errorf("new random bytes generator: %w", err)
	}

	return &RandomBytesGenerator{randomGeneratorBase: rpgBase}, nil
}

func (rpg *RandomBytesGenerator) Generate() []byte {
	return rpg.generate()
}

const alphanumericChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

type RandomASCIIGenerator struct {
	*randomGeneratorBase
}

func newRandomASCIIGenerator(param string) (Generator, error) {
	rpgBase, err := newRandomGeneratorBase(param)
	if err != nil {
		return nil, fmt.Errorf("new random ascii generator: %w", err)
	}

	return &RandomASCIIGenerator{randomGeneratorBase: rpgBase}, nil
}

func (rpg *RandomASCIIGenerator) Generate() []byte {
	junk := rpg.generate()

	result := make([]byte, rpg.size)
	for i, b := range junk {
		result[i] = alphanumericChars[b%byte(len(alphanumericChars))]
	}

	return result
}

type RandomDigitGenerator struct {
	*randomGeneratorBase
}

func newRandomDigitGenerator(param string) (Generator, error) {
	rpgBase, err := newRandomGeneratorBase(param)
	if err != nil {
		return nil, fmt.Errorf("new random digit generator: %w", err)
	}

	return &RandomDigitGenerator{randomGeneratorBase: rpgBase}, nil
}

func (rpg *RandomDigitGenerator) Generate() []byte {
	junk := rpg.generate()

	result := make([]byte, rpg.size)
	for i, b := range junk {
		result[i] = '0' + (b % 10) // Convert to digit character
	}

	return result
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

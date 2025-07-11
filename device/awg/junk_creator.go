package awg

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	v2 "math/rand/v2"
)

type junkCreator struct {
	aSecCfg  aSecCfgType
	cha8Rand *v2.ChaCha8
}

// TODO: refactor param to only pass the junk related params
func NewJunkCreator(aSecCfg aSecCfgType) (junkCreator, error) {
	buf := make([]byte, 32)
	_, err := crand.Read(buf)
	if err != nil {
		return junkCreator{}, err
	}
	return junkCreator{aSecCfg: aSecCfg, cha8Rand: v2.NewChaCha8([32]byte(buf))}, nil
}

// Should be called with aSecMux RLocked
func (jc *junkCreator) CreateJunkPackets(junks *[][]byte) error {
	if jc.aSecCfg.JunkPacketCount == 0 {
		return nil
	}

	for range jc.aSecCfg.JunkPacketCount {
		packetSize := jc.randomPacketSize()
		junk, err := jc.randomJunkWithSize(packetSize)
		if err != nil {
			return fmt.Errorf("create junk packet: %v", err)
		}
		*junks = append(*junks, junk)
	}
	return nil
}

// Should be called with aSecMux RLocked
func (jc *junkCreator) randomPacketSize() int {
	return int(
		jc.cha8Rand.Uint64()%uint64(
			jc.aSecCfg.JunkPacketMaxSize-jc.aSecCfg.JunkPacketMinSize,
		),
	) + jc.aSecCfg.JunkPacketMinSize
}

// Should be called with aSecMux RLocked
func (jc *junkCreator) AppendJunk(writer *bytes.Buffer, size int) error {
	headerJunk, err := jc.randomJunkWithSize(size)
	if err != nil {
		return fmt.Errorf("create header junk: %v", err)
	}
	_, err = writer.Write(headerJunk)
	if err != nil {
		return fmt.Errorf("write header junk: %v", err)
	}
	return nil
}

// Should be called with aSecMux RLocked
func (jc *junkCreator) randomJunkWithSize(size int) ([]byte, error) {
	// TODO: use a memory pool to allocate
	junk := make([]byte, size)
	_, err := jc.cha8Rand.Read(junk)
	return junk, err
}

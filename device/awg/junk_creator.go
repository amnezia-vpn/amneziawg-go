package awg

import (
	"bytes"
	"fmt"
)

type JunkCreator struct {
	cfg             Cfg
	randomGenerator PRNG[int]
}

// TODO: refactor param to only pass the junk related params
func NewJunkCreator(cfg Cfg) JunkCreator {
	return JunkCreator{cfg: cfg, randomGenerator: NewPRNG[int]()}
}

// Should be called with awg mux RLocked
func (jc *JunkCreator) CreateJunkPackets(junks *[][]byte) {
	if jc.cfg.JunkPacketCount == 0 {
		return
	}

	for range jc.cfg.JunkPacketCount {
		packetSize := jc.randomPacketSize()
		junk := jc.randomJunkWithSize(packetSize)
		*junks = append(*junks, junk)
	}
	return
}

// Should be called with awg mux RLocked
func (jc *JunkCreator) randomPacketSize() int {
	return jc.randomGenerator.RandomSizeInRange(jc.cfg.JunkPacketMinSize, jc.cfg.JunkPacketMaxSize)
}

// Should be called with awg mux RLocked
func (jc *JunkCreator) AppendJunk(writer *bytes.Buffer, size int) error {
	headerJunk := jc.randomJunkWithSize(size)
	_, err := writer.Write(headerJunk)
	if err != nil {
		return fmt.Errorf("write header junk: %v", err)
	}
	return nil
}

// Should be called with awg mux RLocked
func (jc *JunkCreator) randomJunkWithSize(size int) []byte {
	return jc.randomGenerator.ReadSize(size)
}

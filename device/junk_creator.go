package device

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	v2 "math/rand/v2"
)

type junkCreator struct {
	device   *Device
	cha8Rand *v2.ChaCha8
}

func NewJunkCreator(d *Device) (junkCreator, error) {
	buf := make([]byte, 32)
	_, err := crand.Read(buf)
	if err != nil {
		return junkCreator{}, err
	}
	return junkCreator{device: d, cha8Rand: v2.NewChaCha8([32]byte(buf))}, nil
}

// Should be called with aSecMux RLocked
func (jc *junkCreator) createJunkPackets(peer *Peer) ([][]byte, error) {
	if jc.device.awg.aSecCfg.junkPacketCount == 0 {
		return nil, nil
	}

	junks := make([][]byte, 0, jc.device.awg.aSecCfg.junkPacketCount)
	for i := 0; i < jc.device.awg.aSecCfg.junkPacketCount; i++ {
		packetSize := jc.randomPacketSize()
		junk, err := jc.randomJunkWithSize(packetSize)
		if err != nil {
			jc.device.log.Errorf(
				"%v - Failed to create junk packet: %v",
				peer,
				err,
			)
			return nil, err
		}
		junks = append(junks, junk)
	}
	return junks, nil
}

// Should be called with aSecMux RLocked
func (jc *junkCreator) randomPacketSize() int {
	return int(
		jc.cha8Rand.Uint64()%uint64(
			jc.device.awg.aSecCfg.junkPacketMaxSize-jc.device.awg.aSecCfg.junkPacketMinSize,
		),
	) + jc.device.awg.aSecCfg.junkPacketMinSize
}

// Should be called with aSecMux RLocked
func (jc *junkCreator) appendJunk(writer *bytes.Buffer, size int) error {
	headerJunk, err := jc.randomJunkWithSize(size)
	if err != nil {
		return fmt.Errorf("failed to create header junk: %v", err)
	}
	_, err = writer.Write(headerJunk)
	if err != nil {
		return fmt.Errorf("failed to write header junk: %v", err)
	}
	return nil
}

// Should be called with aSecMux RLocked
func (jc *junkCreator) randomJunkWithSize(size int) ([]byte, error) {
	junk := make([]byte, size)
	_, err := jc.cha8Rand.Read(junk)
	return junk, err
}

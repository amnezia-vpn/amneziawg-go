package awg

import (
	"fmt"
	"strconv"
)

type TagJunkPacketGenerator struct {
	name     string
	tagValue string

	packetSize int
	generators []Generator
}

func newTagJunkPacketGenerator(name, tagValue string, size int) TagJunkPacketGenerator {
	return TagJunkPacketGenerator{
		name:       name,
		tagValue:   tagValue,
		generators: make([]Generator, 0, size),
	}
}

func (tg *TagJunkPacketGenerator) append(generator Generator) {
	tg.generators = append(tg.generators, generator)
	tg.packetSize += generator.Size()
}

func (tg *TagJunkPacketGenerator) generatePacket() []byte {
	packet := make([]byte, 0, tg.packetSize)
	for _, generator := range tg.generators {
		packet = append(packet, generator.Generate()...)
	}

	return packet
}

func (tg *TagJunkPacketGenerator) Name() string {
	return tg.name
}

func (tg *TagJunkPacketGenerator) nameIndex() (int, error) {
	if len(tg.name) != 2 {
		return 0, fmt.Errorf("name must be 2 character long: %s", tg.name)
	}

	index, err := strconv.Atoi(tg.name[1:2])
	if err != nil {
		return 0, fmt.Errorf("name 2 char should be an int %w", err)
	}
	return index, nil
}

func (tg *TagJunkPacketGenerator) IpcGetFields() IpcFields {
	return IpcFields{
		Key:   tg.name,
		Value: tg.tagValue,
	}
}

package awg

import "fmt"

type TagJunkPacketGenerators struct {
	tagGenerators    []TagJunkPacketGenerator
	length           int
	DefaultJunkCount int // Jc
}

func (generators *TagJunkPacketGenerators) AppendGenerator(
	generator TagJunkPacketGenerator,
) {
	generators.tagGenerators = append(generators.tagGenerators, generator)
	generators.length++
}

func (generators *TagJunkPacketGenerators) IsDefined() bool {
	return len(generators.tagGenerators) > 0
}

// validate that packets were defined consecutively
func (generators *TagJunkPacketGenerators) Validate() error {
	seen := make([]bool, len(generators.tagGenerators))
	for _, generator := range generators.tagGenerators {
		index, err := generator.nameIndex()
		if index > len(generators.tagGenerators) {
			return fmt.Errorf("junk packet index should be consecutive")
		}
		if err != nil {
			return fmt.Errorf("name index: %w", err)
		} else {
			seen[index-1] = true
		}
	}

	for _, found := range seen {
		if !found {
			return fmt.Errorf("junk packet index should be consecutive")
		}
	}

	return nil
}

func (generators *TagJunkPacketGenerators) GeneratePackets() [][]byte {
	var rv = make([][]byte, 0, generators.length+generators.DefaultJunkCount)

	for i, tagGenerator := range generators.tagGenerators {
		rv = append(rv, make([]byte, tagGenerator.packetSize))
		copy(rv[i], tagGenerator.generatePacket())
		PacketCounter.Inc()
	}
	PacketCounter.Add(uint64(generators.DefaultJunkCount))

	return rv
}

func (tg *TagJunkPacketGenerators) IpcGetFields() []IpcFields {
	rv := make([]IpcFields, 0, len(tg.tagGenerators))
	for _, generator := range tg.tagGenerators {
		rv = append(rv, generator.IpcGetFields())
	}

	return rv
}

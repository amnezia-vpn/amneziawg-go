package awg

import (
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/device/awg/internal"
	"github.com/stretchr/testify/require"
)

func TestTagJunkGeneratorHandlerAppendGenerator(t *testing.T) {
	tests := []struct {
		name      string
		generator TagJunkPacketGenerator
	}{
		{
			name:      "append single generator",
			generator: newTagJunkPacketGenerator("t1", "", 10),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			generators := &TagJunkPacketGenerators{}

			// Initial length should be 0
			require.Equal(t, 0, generators.length)
			require.Empty(t, generators.tagGenerators)

			// After append, length should be 1 and generator should be added
			generators.AppendGenerator(tt.generator)
			require.Equal(t, 1, generators.length)
			require.Len(t, generators.tagGenerators, 1)
			require.Equal(t, tt.generator, generators.tagGenerators[0])
		})
	}
}

func TestTagJunkGeneratorHandlerValidate(t *testing.T) {
	tests := []struct {
		name       string
		generators []TagJunkPacketGenerator
		wantErr    bool
		errMsg     string
	}{
		{
			name: "bad start",
			generators: []TagJunkPacketGenerator{
				newTagJunkPacketGenerator("t3", "", 10),
				newTagJunkPacketGenerator("t4", "", 10),
			},
			wantErr: true,
			errMsg:  "junk packet index should be consecutive",
		},
		{
			name: "non-consecutive indices",
			generators: []TagJunkPacketGenerator{
				newTagJunkPacketGenerator("t1", "", 10),
				newTagJunkPacketGenerator("t3", "", 10), // Missing t2
			},
			wantErr: true,
			errMsg:  "junk packet index should be consecutive",
		},
		{
			name: "consecutive indices",
			generators: []TagJunkPacketGenerator{
				newTagJunkPacketGenerator("t1", "", 10),
				newTagJunkPacketGenerator("t2", "", 10),
				newTagJunkPacketGenerator("t3", "", 10),
				newTagJunkPacketGenerator("t4", "", 10),
				newTagJunkPacketGenerator("t5", "", 10),
			},
		},
		{
			name: "nameIndex error",
			generators: []TagJunkPacketGenerator{
				newTagJunkPacketGenerator("error", "", 10),
			},
			wantErr: true,
			errMsg:  "name must be 2 character long",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			generators := &TagJunkPacketGenerators{}
			for _, gen := range tt.generators {
				generators.AppendGenerator(gen)
			}

			err := generators.Validate()
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestTagJunkGeneratorHandlerGenerate(t *testing.T) {
	mockByte1 := []byte{0x01, 0x02}
	mockByte2 := []byte{0x03, 0x04, 0x05}
	mockGen1 := internal.NewMockByteGenerator(mockByte1)
	mockGen2 := internal.NewMockByteGenerator(mockByte2)

	tests := []struct {
		name           string
		setupGenerator func() []TagJunkPacketGenerator
		expected       [][]byte
	}{
		{
			name: "generate with no default junk",
			setupGenerator: func() []TagJunkPacketGenerator {
				tg1 := newTagJunkPacketGenerator("t1", "", 0)
				tg1.append(mockGen1)
				tg1.append(mockGen2)
				tg2 := newTagJunkPacketGenerator("t2", "", 0)
				tg2.append(mockGen2)
				tg2.append(mockGen1)

				return []TagJunkPacketGenerator{tg1, tg2}
			},
			expected: [][]byte{
				append(mockByte1, mockByte2...),
				append(mockByte2, mockByte1...),
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			generators := &TagJunkPacketGenerators{}
			tagGenerators := tt.setupGenerator()
			for _, gen := range tagGenerators {
				generators.AppendGenerator(gen)
			}

			result := generators.GeneratePackets()
			require.Equal(t, result, tt.expected)
		})
	}
}

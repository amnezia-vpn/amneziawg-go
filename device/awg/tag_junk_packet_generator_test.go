package awg

import (
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/device/awg/internal"
	"github.com/stretchr/testify/require"
)

func TestNewTagJunkGenerator(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		genName  string
		size     int
		expected TagJunkPacketGenerator
	}{
		{
			name:    "Create new generator with empty name",
			genName: "",
			size:    0,
			expected: TagJunkPacketGenerator{
				name:       "",
				packetSize: 0,
				generators: make([]Generator, 0),
			},
		},
		{
			name:    "Create new generator with valid name",
			genName: "T1",
			size:    0,
			expected: TagJunkPacketGenerator{
				name:       "T1",
				packetSize: 0,
				generators: make([]Generator, 0),
			},
		},
		{
			name:    "Create new generator with non-zero size",
			genName: "T2",
			size:    5,
			expected: TagJunkPacketGenerator{
				name:       "T2",
				packetSize: 0,
				generators: make([]Generator, 5),
			},
		},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := newTagJunkPacketGenerator(tc.genName, "", tc.size)
			require.Equal(t, tc.expected.name, result.name)
			require.Equal(t, tc.expected.packetSize, result.packetSize)
			require.Equal(t, cap(result.generators), len(tc.expected.generators))
		})
	}
}

func TestTagJunkGeneratorAppend(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		initialState   TagJunkPacketGenerator
		mockSize       int
		expectedLength int
		expectedSize   int
	}{
		{
			name:           "Append to empty generator",
			initialState:   newTagJunkPacketGenerator("T1", "", 0),
			mockSize:       5,
			expectedLength: 1,
			expectedSize:   5,
		},
		{
			name: "Append to non-empty generator",
			initialState: TagJunkPacketGenerator{
				name:       "T2",
				packetSize: 10,
				generators: make([]Generator, 2),
			},
			mockSize:       7,
			expectedLength: 3,  // 2 existing + 1 new
			expectedSize:   17, // 10 + 7
		},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tg := tc.initialState
			mockGen := internal.NewMockGenerator(tc.mockSize)

			tg.append(mockGen)

			require.Equal(t, tc.expectedLength, len(tg.generators))
			require.Equal(t, tc.expectedSize, tg.packetSize)
		})
	}
}

func TestTagJunkGeneratorGenerate(t *testing.T) {
	t.Parallel()

	// Create mock generators for testing
	mockGen1 := internal.NewMockByteGenerator([]byte{0x01, 0x02})
	mockGen2 := internal.NewMockByteGenerator([]byte{0x03, 0x04, 0x05})

	testCases := []struct {
		name           string
		setupGenerator func() TagJunkPacketGenerator
		expected       []byte
	}{
		{
			name: "Generate with empty generators",
			setupGenerator: func() TagJunkPacketGenerator {
				return newTagJunkPacketGenerator("T1", "", 0)
			},
			expected: []byte{},
		},
		{
			name: "Generate with single generator",
			setupGenerator: func() TagJunkPacketGenerator {
				tg := newTagJunkPacketGenerator("T2", "", 0)
				tg.append(mockGen1)
				return tg
			},
			expected: []byte{0x01, 0x02},
		},
		{
			name: "Generate with multiple generators",
			setupGenerator: func() TagJunkPacketGenerator {
				tg := newTagJunkPacketGenerator("T3", "", 0)
				tg.append(mockGen1)
				tg.append(mockGen2)
				return tg
			},
			expected: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tg := tc.setupGenerator()
			result := tg.generatePacket()

			require.Equal(t, tc.expected, result)
		})
	}
}

func TestTagJunkGeneratorNameIndex(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		generatorName string
		expectedIndex int
		expectError   bool
	}{
		{
			name:          "Valid name with digit",
			generatorName: "T5",
			expectedIndex: 5,
			expectError:   false,
		},
		{
			name:          "Invalid name - too short",
			generatorName: "T",
			expectError:   true,
		},
		{
			name:          "Invalid name - too long",
			generatorName: "T55",
			expectError:   true,
		},
		{
			name:          "Invalid name - non-digit second character",
			generatorName: "TX",
			expectError:   true,
		},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tg := TagJunkPacketGenerator{name: tc.generatorName}
			index, err := tg.nameIndex()

			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expectedIndex, index)
			}
		})
	}
}

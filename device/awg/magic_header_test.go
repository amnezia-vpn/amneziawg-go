package awg

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewMagicHeaderSameValue(t *testing.T) {
	tests := []struct {
		name     string
		value    uint32
		expected MagicHeader
	}{
		{
			name:     "zero value",
			value:    0,
			expected: MagicHeader{Min: 0, Max: 0},
		},
		{
			name:     "small value",
			value:    1,
			expected: MagicHeader{Min: 1, Max: 1},
		},
		{
			name:     "large value",
			value:    4294967295, // max uint32
			expected: MagicHeader{Min: 4294967295, Max: 4294967295},
		},
		{
			name:     "medium value",
			value:    1000,
			expected: MagicHeader{Min: 1000, Max: 1000},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := NewMagicHeaderSameValue(tt.value)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestNewMagicHeader(t *testing.T) {
	tests := []struct {
		name     string
		min      uint32
		max      uint32
		expected MagicHeader
		errorMsg string
	}{
		{
			name:     "valid range",
			min:      1,
			max:      10,
			expected: MagicHeader{Min: 1, Max: 10},
		},
		{
			name:     "equal values",
			min:      5,
			max:      5,
			expected: MagicHeader{Min: 5, Max: 5},
		},
		{
			name:     "zero range",
			min:      0,
			max:      0,
			expected: MagicHeader{Min: 0, Max: 0},
		},
		{
			name:     "max uint32 range",
			min:      4294967294,
			max:      4294967295,
			expected: MagicHeader{Min: 4294967294, Max: 4294967295},
		},
		{
			name:     "min greater than max",
			min:      10,
			max:      5,
			expected: MagicHeader{},
			errorMsg: "min (10) cannot be greater than max (5)",
		},
		{
			name:     "large min greater than max",
			min:      4294967295,
			max:      1,
			expected: MagicHeader{},
			errorMsg: "min (4294967295) cannot be greater than max (1)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := NewMagicHeader(tt.min, tt.max)

			if tt.errorMsg != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorMsg)
				require.Equal(t, MagicHeader{}, result)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestParseMagicHeader(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    string
		expected MagicHeader
		errorMsg string
	}{
		{
			name:     "single value",
			key:      "header1",
			value:    "100",
			expected: MagicHeader{Min: 100, Max: 100},
		},
		{
			name:     "valid range",
			key:      "header2",
			value:    "10-20",
			expected: MagicHeader{Min: 10, Max: 20},
		},
		{
			name:     "zero single value",
			key:      "header3",
			value:    "0",
			expected: MagicHeader{Min: 0, Max: 0},
		},
		{
			name:     "zero range",
			key:      "header4",
			value:    "0-0",
			expected: MagicHeader{Min: 0, Max: 0},
		},
		{
			name:     "max uint32 single",
			key:      "header5",
			value:    "4294967295",
			expected: MagicHeader{Min: 4294967295, Max: 4294967295},
		},
		{
			name:     "max uint32 range",
			key:      "header6",
			value:    "4294967294-4294967295",
			expected: MagicHeader{Min: 4294967294, Max: 4294967295},
		},
		{
			name:     "invalid single value - not number",
			key:      "header7",
			value:    "abc",
			expected: MagicHeader{},
			errorMsg: "parse key: header7; value: abc;",
		},
		{
			name:     "invalid single value - negative",
			key:      "header8",
			value:    "-5",
			expected: MagicHeader{},
			errorMsg: "invalid value for key: header8; value: -5;",
		},
		{
			name:     "invalid single value - too large",
			key:      "header9",
			value:    "4294967296",
			expected: MagicHeader{},
			errorMsg: "parse key: header9; value: 4294967296;",
		},
		{
			name:     "invalid range - min not number",
			key:      "header10",
			value:    "abc-10",
			expected: MagicHeader{},
			errorMsg: "parse min key: header10; value: abc;",
		},
		{
			name:     "invalid range - max not number",
			key:      "header11",
			value:    "10-abc",
			expected: MagicHeader{},
			errorMsg: "parse max key: header11; value: abc;",
		},
		{
			name:     "invalid range - min greater than max",
			key:      "header12",
			value:    "20-10",
			expected: MagicHeader{},
			errorMsg: "new magicHeader key: header12; value: 20-10;",
		},
		{
			name:     "invalid range - too many parts",
			key:      "header13",
			value:    "10-20-30",
			expected: MagicHeader{},
			errorMsg: "parse key: header13; value: 10-20-30;",
		},
		{
			name:     "empty value",
			key:      "header14",
			value:    "",
			expected: MagicHeader{},
			errorMsg: "parse key: header14; value: ;",
		},
		{
			name:     "hyphen only",
			key:      "header15",
			value:    "-",
			expected: MagicHeader{},
			errorMsg: "invalid value for key: header15; value: -;",
		},
		{
			name:     "empty min",
			key:      "header16",
			value:    "-10",
			expected: MagicHeader{},
			errorMsg: "invalid value for key: header16; value: -10;",
		},
		{
			name:     "empty max",
			key:      "header17",
			value:    "10-",
			expected: MagicHeader{},
			errorMsg: "invalid value for key: header17; value: 10-;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := ParseMagicHeader(tt.key, tt.value)

			if tt.errorMsg != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorMsg)
				require.Equal(t, MagicHeader{}, result)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestNewMagicHeaders(t *testing.T) {
	tests := []struct {
		name         string
		magicHeaders []MagicHeader
		errorMsg     string
	}{
		{
			name: "valid non-overlapping headers",
			magicHeaders: []MagicHeader{
				{Min: 1, Max: 10},
				{Min: 11, Max: 20},
				{Min: 21, Max: 30},
				{Min: 31, Max: 40},
			},
		},
		{
			name: "valid adjacent headers",
			magicHeaders: []MagicHeader{
				{Min: 1, Max: 1},
				{Min: 2, Max: 2},
				{Min: 3, Max: 3},
				{Min: 4, Max: 4},
			},
		},
		{
			name: "valid zero-based headers",
			magicHeaders: []MagicHeader{
				{Min: 0, Max: 0},
				{Min: 1, Max: 1},
				{Min: 2, Max: 2},
				{Min: 3, Max: 3},
			},
		},
		{
			name: "valid large value headers",
			magicHeaders: []MagicHeader{
				{Min: 4294967290, Max: 4294967291},
				{Min: 4294967292, Max: 4294967293},
				{Min: 4294967294, Max: 4294967294},
				{Min: 4294967295, Max: 4294967295},
			},
		},
		{
			name: "too few headers",
			magicHeaders: []MagicHeader{
				{Min: 1, Max: 10},
				{Min: 11, Max: 20},
				{Min: 21, Max: 30},
			},
			errorMsg: "all header types should be included:",
		},
		{
			name: "too many headers",
			magicHeaders: []MagicHeader{
				{Min: 1, Max: 10},
				{Min: 11, Max: 20},
				{Min: 21, Max: 30},
				{Min: 31, Max: 40},
				{Min: 41, Max: 50},
			},
			errorMsg: "all header types should be included:",
		},
		{
			name:         "empty headers",
			magicHeaders: []MagicHeader{},
			errorMsg:     "all header types should be included:",
		},
		{
			name: "overlapping headers",
			magicHeaders: []MagicHeader{
				{Min: 1, Max: 15},
				{Min: 10, Max: 20},
				{Min: 25, Max: 30},
				{Min: 35, Max: 40},
			},
			errorMsg: "magic headers shouldn't overlap;",
		},
		{
			name: "overlapping headers at limit-first",
			magicHeaders: []MagicHeader{
				{Min: 1, Max: 10},
				{Min: 10, Max: 20},
				{Min: 25, Max: 30},
				{Min: 35, Max: 40},
			},
			errorMsg: "magic headers shouldn't overlap;",
		},
		{
			name: "overlapping headers at limit-second",
			magicHeaders: []MagicHeader{
				{Min: 1, Max: 10},
				{Min: 15, Max: 25},
				{Min: 25, Max: 30},
				{Min: 35, Max: 40},
			},
			errorMsg: "magic headers shouldn't overlap;",
		},
		{
			name: "overlapping headers at limit-third",
			magicHeaders: []MagicHeader{
				{Min: 1, Max: 10},
				{Min: 15, Max: 25},
				{Min: 30, Max: 35},
				{Min: 35, Max: 40},
			},
			errorMsg: "magic headers shouldn't overlap;",
		},
		{
			name: "identical ranges",
			magicHeaders: []MagicHeader{
				{Min: 10, Max: 20},
				{Min: 10, Max: 20},
				{Min: 25, Max: 30},
				{Min: 35, Max: 40},
			},
			errorMsg: "magic headers shouldn't overlap;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := NewMagicHeaders(tt.magicHeaders)

			if tt.errorMsg != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorMsg)
				require.Equal(t, MagicHeaders{}, result)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.magicHeaders, result.Values)
				require.NotNil(t, result.randomGenerator)
			}
		})
	}
}

// Mock PRNG for testing
type mockPRNG struct {
	returnValue uint32
}

func (m *mockPRNG) RandomSizeInRange(min, max uint32) uint32 {
	return m.returnValue
}

func (m *mockPRNG) Get() uint64 {
	return 0
}
func (m *mockPRNG) ReadSize(size int) []byte {
	return make([]byte, size)
}

func TestMagicHeaders_Get(t *testing.T) {
	// Create test headers
	headers := []MagicHeader{
		{Min: 1, Max: 10},
		{Min: 11, Max: 20},
		{Min: 21, Max: 30},
		{Min: 31, Max: 40},
	}

	tests := []struct {
		name           string
		defaultMsgType uint32
		mockValue      uint32
		expectedValue  uint32
		errorMsg       string
	}{
		{
			name:           "valid type 1",
			defaultMsgType: 1,
			mockValue:      5,
			expectedValue:  5,
		},
		{
			name:           "valid type 2",
			defaultMsgType: 2,
			mockValue:      15,
			expectedValue:  15,
		},
		{
			name:           "valid type 3",
			defaultMsgType: 3,
			mockValue:      25,
			expectedValue:  25,
		},
		{
			name:           "valid type 4",
			defaultMsgType: 4,
			mockValue:      35,
			expectedValue:  35,
		},
		{
			name:           "invalid type 0",
			defaultMsgType: 0,
			mockValue:      0,
			expectedValue:  0,
			errorMsg:       "invalid msg type: 0",
		},
		{
			name:           "invalid type 5",
			defaultMsgType: 5,
			mockValue:      0,
			expectedValue:  0,
			errorMsg:       "invalid msg type: 5",
		},
		{
			name:           "invalid type max uint32",
			defaultMsgType: 4294967295,
			mockValue:      0,
			expectedValue:  0,
			errorMsg:       "invalid msg type: 4294967295",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Create a new instance with mock PRNG for each test
			testMagicHeaders := MagicHeaders{
				Values:          headers,
				randomGenerator: &mockPRNG{returnValue: tt.mockValue},
			}

			result, err := testMagicHeaders.Get(tt.defaultMsgType)

			if tt.errorMsg != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorMsg)
				require.Equal(t, uint32(0), result)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedValue, result)
			}
		})
	}
}

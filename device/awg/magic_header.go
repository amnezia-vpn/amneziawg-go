package awg

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

type MagicHeader struct {
	Min uint32
	Max uint32
}

func NewMagicHeaderSameValue(value uint32) MagicHeader {
	return MagicHeader{Min: value, Max: value}
}

func NewMagicHeader(min, max uint32) (MagicHeader, error) {
	if min > max {
		return MagicHeader{}, fmt.Errorf("min (%d) cannot be greater than max (%d)", min, max)
	}

	return MagicHeader{Min: min, Max: max}, nil
}

func ParseMagicHeader(key, value string) (MagicHeader, error) {
	hyphenIdx := strings.Index(value, "-")
	if hyphenIdx == -1 {
		// if there is no hyphen, we treat it as single magic header value
		magicHeader, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return MagicHeader{}, fmt.Errorf("parse key: %s; value: %s; %w", key, value, err)
		}

		return NewMagicHeader(uint32(magicHeader), uint32(magicHeader))
	}

	minStr := value[:hyphenIdx]
	maxStr := value[hyphenIdx+1:]
	if len(minStr) == 0 || len(maxStr) == 0 {
		return MagicHeader{}, fmt.Errorf("invalid value for key: %s; value: %s; expected format: min-max", key, value)
	}

	min, err := strconv.ParseUint(minStr, 10, 32)
	if err != nil {
		return MagicHeader{}, fmt.Errorf("parse min key: %s; value: %s; %w", key, minStr, err)
	}

	max, err := strconv.ParseUint(maxStr, 10, 32)
	if err != nil {
		return MagicHeader{}, fmt.Errorf("parse max key: %s; value: %s; %w", key, maxStr, err)
	}

	magicHeader, err := NewMagicHeader(uint32(min), uint32(max))
	if err != nil {
		return MagicHeader{}, fmt.Errorf("new magicHeader key: %s; value: %s-%s; %w", key, minStr, maxStr, err)
	}

	return magicHeader, nil
}

type MagicHeaders struct {
	Values          []MagicHeader
	randomGenerator RandomNumberGenerator[uint32]
}

func NewMagicHeaders(headerValues []MagicHeader) (MagicHeaders, error) {
	if len(headerValues) != 4 {
		return MagicHeaders{}, fmt.Errorf("all header types should be included: %v", headerValues)
	}

	sortedMagicHeaders := slices.SortedFunc(slices.Values(headerValues), func(lhs MagicHeader, rhs MagicHeader) int {
		return cmp.Compare(lhs.Min, rhs.Min)
	})

	for i := range 3 {
		if sortedMagicHeaders[i].Max >= sortedMagicHeaders[i+1].Min {
			return MagicHeaders{}, fmt.Errorf(
				"magic headers shouldn't overlap; %v > %v",
				sortedMagicHeaders[i].Max,
				sortedMagicHeaders[i+1].Min,
			)
		}
	}

	return MagicHeaders{Values: headerValues, randomGenerator: NewPRNG[uint32]()}, nil
}

func (mh *MagicHeaders) Get(defaultMsgType uint32) (uint32, error) {
	if defaultMsgType == 0 || defaultMsgType > 4 {
		return 0, fmt.Errorf("invalid msg type: %d", defaultMsgType)
	}

	return mh.randomGenerator.RandomSizeInRange(mh.Values[defaultMsgType-1].Min, mh.Values[defaultMsgType-1].Max), nil
}

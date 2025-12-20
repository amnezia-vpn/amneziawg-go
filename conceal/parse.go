package conceal

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type obfBuilder func(val string) (Obf, error)

var obfBuilders = map[string]obfBuilder{
	"b":  buildBytesObf,
	"t":  buildTimestampObf,
	"r":  buildRandObf,
	"rc": buildRandCharObf,
	"rd": buildRandDigitsObf,
	"d":  buildDataObf,
	"ds": buildDataStringObf,
	"dz": buildDataSizeObf,
}

func BuildObfs(spec string) (Obfs, error) {
	var (
		obfs Obfs
		errs []error
	)

	remaining := spec[:]
	for {
		start := strings.IndexByte(remaining, '<')
		if start == -1 {
			break
		}

		end := strings.IndexByte(remaining[start:], '>')
		if end == -1 {
			return nil, errors.New("missing enclosing >")
		}
		end += start

		tag := remaining[start+1 : end]
		parts := strings.Fields(tag)
		if len(parts) == 0 {
			errs = append(errs, errors.New("empty tag"))
			remaining = remaining[end+1:]
			continue
		}

		key := parts[0]
		builder, ok := obfBuilders[key]
		if !ok {
			errs = append(errs, fmt.Errorf("unknown tag <%s>", key))
			remaining = remaining[end+1:]
			continue
		}

		val := ""
		if len(parts) > 1 {
			val = parts[1]
		}

		o, err := builder(val)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to build <%s>: %w", key, err))
			remaining = remaining[end+1:]
			continue
		}

		obfs = append(obfs, o)
		remaining = remaining[end+1:]
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return obfs, nil
}

func buildTimestampObf(_ string) (Obf, error) {
	return &timestampObf{}, nil
}

func buildRandDigitsObf(val string) (Obf, error) {
	length, err := strconv.Atoi(val)
	if err != nil {
		return nil, err
	}

	return &randDigitObf{
		length: length,
	}, nil
}

func buildRandCharObf(val string) (Obf, error) {
	length, err := strconv.Atoi(val)
	if err != nil {
		return nil, err
	}

	return &randCharObf{
		length: length,
	}, nil
}

func buildRandObf(val string) (Obf, error) {
	length, err := strconv.Atoi(val)
	if err != nil {
		return nil, err
	}

	return &randObf{
		length: length,
	}, nil
}

func buildDataSizeObf(val string) (Obf, error) {
	length, err := strconv.Atoi(val)
	if err != nil {
		return nil, err
	}

	return &dataSizeObf{
		length: length,
	}, nil
}

func buildDataObf(val string) (Obf, error) {
	return &dataObf{}, nil
}

func buildBytesObf(val string) (Obf, error) {
	val = strings.TrimPrefix(val, "0x")

	if len(val) == 0 {
		return nil, errors.New("empty argument")
	}

	if len(val)%2 != 0 {
		return nil, errors.New("odd amount of symbols")
	}

	bytes, err := hex.DecodeString(val)
	if err != nil {
		return nil, err
	}

	return &bytesObf{data: bytes}, nil
}

func buildDataStringObf(val string) (Obf, error) {
	return &dataStringObf{}, nil
}

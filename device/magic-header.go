package device

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type magicHeader struct {
	start uint32
	end   uint32
}

func newMagicHeader(spec string) (*magicHeader, error) {
	parts := strings.Split(spec, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return nil, errors.New("bad format")
	}

	start, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", parts[0], err)
	}

	var end uint64
	if len(parts) > 1 {
		end, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", parts[1], err)
		}
	} else {
		end = start
	}

	if end < start {
		return nil, errors.New("wrong range specified")
	}

	return &magicHeader{
		start: uint32(start),
		end:   uint32(end),
	}, nil
}

func (h *magicHeader) GenSpec() string {
	if h.start == h.end {
		return fmt.Sprintf("%d", h.start)
	}
	return fmt.Sprintf("%d-%d", h.start, h.end)
}

func (h *magicHeader) Validate(val uint32) bool {
	return h.start <= val && val <= h.end
}

func (h *magicHeader) Generate() uint32 {
	return randUint(h.start, h.end)
}

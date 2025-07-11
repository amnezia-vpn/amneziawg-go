package awg

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/tevino/abool"
)

type aSecCfgType struct {
	IsSet                      bool
	JunkPacketCount            int
	JunkPacketMinSize          int
	JunkPacketMaxSize          int
	InitHeaderJunkSize         int
	ResponseHeaderJunkSize     int
	CookieReplyHeaderJunkSize  int
	TransportHeaderJunkSize    int
	InitPacketMagicHeader      uint32
	ResponsePacketMagicHeader  uint32
	UnderloadPacketMagicHeader uint32
	TransportPacketMagicHeader uint32
	// InitPacketMagicHeader      Limit
	// ResponsePacketMagicHeader  Limit
	// UnderloadPacketMagicHeader Limit
	// TransportPacketMagicHeader Limit
}

type Limit struct {
	Min        uint32
	Max        uint32
	HeaderType uint32
}

func NewLimit(min, max, headerType uint32) (Limit, error) {
	if min > max {
		return Limit{}, fmt.Errorf("min (%d) cannot be greater than max (%d)", min, max)
	}

	return Limit{
		Min:        min,
		Max:        max,
		HeaderType: headerType,
	}, nil
}

func ParseMagicHeader(key, value string, defaultHeaderType uint32) (Limit, error) {
	// tempAwg.ASecCfg.InitPacketMagicHeader, err = awg.NewLimit(uint32(initPacketMagicHeaderMin), uint32(initPacketMagicHeaderMax), DNewLimit(min, max, headerType)efaultMessageInitiationType)
	// var min, max, headerType uint32
	// _, err := fmt.Sscanf(value, "%d-%d:%d", &min, &max, &headerType)
	// if err != nil {
	// 	return Limit{}, fmt.Errorf("invalid magic header format: %s", value)
	// }

	limits := strings.Split(value, "-")
	if len(limits) != 2 {
		return Limit{}, fmt.Errorf("invalid format for key: %s; %s", key, value)
	}

	min, err := strconv.ParseUint(limits[0], 10, 32)
	if err != nil {
		return Limit{}, fmt.Errorf("parse min key: %s; value: ; %w", key, limits[0], err)
	}

	max, err := strconv.ParseUint(limits[1], 10, 32)
	if err != nil {
		return Limit{}, fmt.Errorf("parse max key: %s; value: ; %w", key, limits[0], err)
	}

	limit, err := NewLimit(uint32(min), uint32(max), defaultHeaderType)
	if err != nil {
		return Limit{}, fmt.Errorf("new lmit key: %s; value: ; %w", key, limits[0], err)
	}

	return limit, nil
}

type Limits []Limit

func NewLimits(limits []Limit) Limits {
	slices.SortFunc(limits, func(a, b Limit) int {
		if a.Min < b.Min {
			return -1
		} else if a.Min > b.Min {
			return 1
		}
		return 0
	})

	return Limits(limits)
}

type Protocol struct {
	IsASecOn abool.AtomicBool
	// TODO: revision the need of the mutex
	ASecMux     sync.RWMutex
	ASecCfg     aSecCfgType
	JunkCreator junkCreator

	HandshakeHandler SpecialHandshakeHandler
}

func (protocol *Protocol) CreateInitHeaderJunk() ([]byte, error) {
	return protocol.createHeaderJunk(protocol.ASecCfg.InitHeaderJunkSize)
}

func (protocol *Protocol) CreateResponseHeaderJunk() ([]byte, error) {
	return protocol.createHeaderJunk(protocol.ASecCfg.ResponseHeaderJunkSize)
}

func (protocol *Protocol) CreateCookieReplyHeaderJunk() ([]byte, error) {
	return protocol.createHeaderJunk(protocol.ASecCfg.CookieReplyHeaderJunkSize)
}

func (protocol *Protocol) CreateTransportHeaderJunk(packetSize int) ([]byte, error) {
	return protocol.createHeaderJunk(protocol.ASecCfg.TransportHeaderJunkSize, packetSize)
}

func (protocol *Protocol) createHeaderJunk(junkSize int, optExtraSize ...int) ([]byte, error) {
	extraSize := 0
	if len(optExtraSize) == 1 {
		extraSize = optExtraSize[0]
	}

	var junk []byte
	protocol.ASecMux.RLock()
	if junkSize != 0 {
		buf := make([]byte, 0, junkSize+extraSize)
		writer := bytes.NewBuffer(buf[:0])
		err := protocol.JunkCreator.AppendJunk(writer, junkSize)
		if err != nil {
			protocol.ASecMux.RUnlock()
			return nil, err
		}
		junk = writer.Bytes()
	}
	protocol.ASecMux.RUnlock()

	return junk, nil
}

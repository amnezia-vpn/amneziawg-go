package conceal

import (
	"encoding/binary"
	"errors"
	"sync"
)

// UDPDatagramPipeline applies UDP conceal transforms at datagram boundaries.
// It is transport-agnostic and can therefore be reused by different UDP binds.
type UDPDatagramPipeline struct {
	pool *BufferPool

	classifier packetClassifier

	framing       frameEncoding
	framingActive bool

	masquerade       masqueradeEncoding
	masqueradeActive bool

	preludeActive bool
	rulesArr      [5]Rules
	junkCount     int
	junkGen       *junkGenerator
}

func NewUDPDatagramPipeline(
	pool *sync.Pool,
	framedOpts FramedOpts,
	preludeOpts PreludeOpts,
	masqueradeOpts MasqueradeOpts,
) *UDPDatagramPipeline {
	if preludeOpts.Jmin > preludeOpts.Jmax {
		preludeOpts.Jmin, preludeOpts.Jmax = preludeOpts.Jmax, preludeOpts.Jmin
	}

	pipeline := &UDPDatagramPipeline{
		pool:          WrapBufferPool(pool),
		classifier:    newPacketClassifier(framedOpts),
		preludeActive: !preludeOpts.IsEmpty(),
		rulesArr:      preludeOpts.RulesArr,
		junkCount:     preludeOpts.Jc,
	}

	if pipeline.junkCount > 0 {
		pipeline.junkGen = newJunkGenerator(preludeOpts.Jmin, preludeOpts.Jmax)
	}

	pipeline.framing, pipeline.framingActive = newFrameEncoding(framedOpts)
	pipeline.masquerade, pipeline.masqueradeActive = newMasqueradeEncoding(pipeline.pool, masqueradeOpts)

	return pipeline
}

func (p *UDPDatagramPipeline) Active() bool {
	return p.preludeActive || p.framingActive || p.masqueradeActive
}

func (p *UDPDatagramPipeline) Encode(dst, src []byte) (int, error) {
	data := src

	if p.framingActive && p.masqueradeActive {
		tmp := p.pool.Get()
		n := p.framing.Encode(tmp, src)
		if n == 0 {
			n = copy(tmp, src)
		}
		data = tmp[:n]
		defer p.pool.Put(tmp)
	}

	if p.framingActive && !p.masqueradeActive {
		n := p.framing.Encode(dst, src)
		if n == 0 {
			n = copy(dst, src)
		}
		return n, nil
	}

	if p.masqueradeActive {
		return p.masquerade.Encode(dst, data)
	}

	return copy(dst, data), nil
}

func (p *UDPDatagramPipeline) DecodeInPlace(buf []byte, n int) (int, bool) {
	n, err := p.DecodeInPlaceErr(buf, n)
	return n, err == nil
}

func (p *UDPDatagramPipeline) DecodeInPlaceErr(buf []byte, n int) (int, error) {
	if p.masqueradeActive {
		var err error
		n, err = p.masquerade.DecodeInPlace(buf, n)
		if err != nil {
			if !errors.Is(err, ErrFormat) {
				err = NewFormatError(buf[:n], err)
			}
			return 0, err
		}
	}

	if p.framingActive {
		var err error
		n, err = p.framing.Decode(buf[:n])
		if err != nil {
			return 0, err
		}
	}

	if !p.classifier.IsValid(buf[:n]) {
		return 0, NewFormatError(buf[:n], errInvalidData)
	}

	return n, nil
}

func (p *UDPDatagramPipeline) EmitPrelude(packet []byte, emit func([]byte) error) error {
	if !p.preludeActive || !p.classifier.MatchesInitiationHeader(packet) {
		return nil
	}

	buf := p.pool.Get()
	defer p.pool.Put(buf)

	ctx := writeContext{
		FlexBuffer: WrapFlexBuffer(nil),
		BufferPool: p.pool,
	}
	w := newSliceWriter(buf)

	for _, rules := range p.rulesArr {
		if rules == nil {
			continue
		}

		w.Reset(buf)
		if err := rules.Write(&w, &ctx); err != nil {
			return err
		}

		if err := emit(w.Bytes()); err != nil {
			return err
		}
	}

	for range p.junkCount {
		if err := emit(p.junkGen.generate(buf)); err != nil {
			return err
		}
	}

	return nil
}

type packetClassifier struct {
	header struct {
		initial   RangedHeader
		response  RangedHeader
		cookie    RangedHeader
		transport RangedHeader
	}
}

func newPacketClassifier(opts FramedOpts) packetClassifier {
	classifier := packetClassifier{}

	if opts.HeaderCompat && opts.H1 != nil {
		classifier.header.initial = *opts.H1
	} else {
		classifier.header.initial = RangedHeader{WireguardMsgInitiationType, WireguardMsgInitiationType}
	}

	if opts.HeaderCompat && opts.H2 != nil {
		classifier.header.response = *opts.H2
	} else {
		classifier.header.response = RangedHeader{WireguardMsgResponseType, WireguardMsgResponseType}
	}

	if opts.HeaderCompat && opts.H3 != nil {
		classifier.header.cookie = *opts.H3
	} else {
		classifier.header.cookie = RangedHeader{WireguardMsgCookieReplyType, WireguardMsgCookieReplyType}
	}

	if opts.HeaderCompat && opts.H4 != nil {
		classifier.header.transport = *opts.H4
	} else {
		classifier.header.transport = RangedHeader{WireguardMsgTransportType, WireguardMsgTransportType}
	}

	return classifier
}

func (c packetClassifier) packetKind(packet []byte) frameRecordKind {
	if len(packet) < 4 {
		return frameRecordInvalid
	}

	header := binary.LittleEndian.Uint32(packet[:4])

	switch {
	case len(packet) == WireguardMsgInitiationSize && c.header.initial.Validate(header):
		return frameRecordInitiation
	case len(packet) == WireguardMsgResponseSize && c.header.response.Validate(header):
		return frameRecordResponse
	case len(packet) == WireguardMsgCookieReplySize && c.header.cookie.Validate(header):
		return frameRecordCookie
	case len(packet) >= WireguardMsgTransportMinSize && c.header.transport.Validate(header):
		return frameRecordTransport
	default:
		return frameRecordInvalid
	}
}

func (c packetClassifier) IsValid(packet []byte) bool {
	return c.packetKind(packet) != frameRecordInvalid
}

func (c packetClassifier) IsInitiation(packet []byte) bool {
	return c.packetKind(packet) == frameRecordInitiation
}

func (c packetClassifier) MatchesInitiationHeader(packet []byte) bool {
	if len(packet) < 4 {
		return false
	}
	return c.header.initial.Validate(binary.LittleEndian.Uint32(packet[:4]))
}

type masqueradeEncoding struct {
	rulesIn  Rules
	rulesOut Rules
	pool     *BufferPool
}

func newMasqueradeEncoding(pool *BufferPool, opts MasqueradeOpts) (masqueradeEncoding, bool) {
	if opts.RulesIn == nil && opts.RulesOut == nil {
		return masqueradeEncoding{}, false
	}

	return masqueradeEncoding{
		rulesIn:  opts.RulesIn,
		rulesOut: opts.RulesOut,
		pool:     pool,
	}, true
}

func (e masqueradeEncoding) DecodeInPlace(buf []byte, n int) (int, error) {
	if e.rulesIn == nil {
		return n, nil
	}

	r := newSliceReader(buf[:n])
	ctx := readContext{
		FlexBuffer: WrapFlexBuffer(buf),
		BufferPool: e.pool,
	}

	if err := e.rulesIn.Read(&r, &ctx); err != nil {
		return 0, err
	}

	return ctx.Len(), nil
}

func (e masqueradeEncoding) Encode(dst, src []byte) (int, error) {
	if e.rulesOut == nil {
		return copy(dst, src), nil
	}

	ctx := writeContext{
		FlexBuffer: WrapFlexBuffer(src),
		BufferPool: e.pool,
	}

	w := newSliceWriter(dst)
	if err := e.rulesOut.Write(&w, &ctx); err != nil {
		return 0, err
	}

	return len(w.Bytes()), nil
}

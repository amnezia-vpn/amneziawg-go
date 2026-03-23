package conn

import (
	"net"

	"github.com/amnezia-vpn/amneziawg-go/conceal"
)

type Framable interface {
	SetFramedOpts(opts conceal.FramedOpts)
}

type Preludable interface {
	SetPreludeOpts(opts conceal.PreludeOpts)
}

type Masqueradable interface {
	SetMasqueradeOpts(opts conceal.MasqueradeOpts)
}

type concealStage string

const (
	concealStageMasquerade concealStage = "masquerade"
	concealStageRecord     concealStage = "record"
	concealStageFramed     concealStage = "framed"
	concealStagePrelude    concealStage = "prelude"
)

type concealPipeline struct {
	stages []concealStage
}

func (p concealPipeline) names() []string {
	names := make([]string, 0, len(p.stages))
	for _, stage := range p.stages {
		names = append(names, string(stage))
	}
	return names
}

func hasFramed(opts conceal.FramedOpts) bool {
	return opts.H1 != nil || opts.H2 != nil || opts.H3 != nil || opts.H4 != nil ||
		opts.S1 != 0 || opts.S2 != 0 || opts.S3 != 0 || opts.S4 != 0
}

func hasMasquerade(opts conceal.MasqueradeOpts) bool {
	return opts.RulesIn != nil || opts.RulesOut != nil
}

func hasBidirectionalStreamRecords(opts conceal.MasqueradeOpts) bool {
	return opts.RulesIn != nil && opts.RulesOut != nil
}

func udpPreludeHeader(opts conceal.FramedOpts) *conceal.RangedHeader {
	if opts.HeaderCompat {
		return opts.H1
	}
	return nil
}

func (b *StdNetBind) udpConcealPipeline() concealPipeline {
	stages := make([]concealStage, 0, 3)
	if hasMasquerade(b.masqueradeOpts) {
		stages = append(stages, concealStageMasquerade)
	}
	if hasFramed(b.framedOpts) {
		stages = append(stages, concealStageFramed)
	}
	if !b.preludeOpts.IsEmpty() {
		stages = append(stages, concealStagePrelude)
	}
	return concealPipeline{stages: stages}
}

func (b *StdNetBind) batchConcealPipeline() concealPipeline {
	return b.udpConcealPipeline()
}

func (b *BindStream) streamConcealPipeline() concealPipeline {
	stages := make([]concealStage, 0, 3)
	if hasMasquerade(b.masqueradeOpts) {
		stages = append(stages, concealStageRecord)
	}
	if b.preludeOpts.HasDecoyRules() && hasBidirectionalStreamRecords(b.masqueradeOpts) {
		stages = append(stages, concealStagePrelude)
	}
	if hasFramed(b.framedOpts) {
		stages = append(stages, concealStageFramed)
	}
	return concealPipeline{stages: stages}
}

func (b *StdNetBind) upgradeUDPConn(conn UDPConn) UDPConn {
	origin := conn
	for _, stage := range b.udpConcealPipeline().stages {
		switch stage {
		case concealStageMasquerade:
			if masquerade, ok := conceal.NewMasqueradeUDPConn(conn, &b.bufPool, b.masqueradeOpts); ok {
				conn = masquerade
			}
		case concealStageFramed:
			if framed, ok := conceal.NewFramedUDPConn(conn, &b.bufPool, b.framedOpts); ok {
				conn = framed
			}
		case concealStagePrelude:
			if prelude, ok := conceal.NewPreludeUDPConn(conn, origin, &b.bufPool, udpPreludeHeader(b.framedOpts), b.preludeOpts); ok {
				conn = prelude
			}
		}
	}
	return conn
}

func (b *StdNetBind) upgradePacketConn(conn LinuxPacketConn) LinuxPacketConn {
	origin := conn
	for _, stage := range b.batchConcealPipeline().stages {
		switch stage {
		case concealStageMasquerade:
			if masquerade, ok := conceal.NewMasqueradeBatchConn(conn, &b.bufPool, b.masqueradeOpts); ok {
				conn = masquerade
			}
		case concealStageFramed:
			if framed, ok := conceal.NewFramedBatchConn(conn, &b.bufPool, b.framedOpts); ok {
				conn = framed
			}
		case concealStagePrelude:
			if prelude, ok := conceal.NewPreludeBatchConn(conn, origin, &b.bufPool, &b.msgsPool, udpPreludeHeader(b.framedOpts), b.preludeOpts); ok {
				conn = prelude
			}
		}
	}
	return conn
}

func (b *StdNetBind) SetFramedOpts(opts conceal.FramedOpts) {
	b.framedOpts = opts
}

func (b *StdNetBind) SetPreludeOpts(opts conceal.PreludeOpts) {
	b.preludeOpts = opts
}

func (b *StdNetBind) SetMasqueradeOpts(opts conceal.MasqueradeOpts) {
	b.masqueradeOpts = opts
}

func (b *BindStream) upgradeConn(conn net.Conn) net.Conn {
	var recordConn conceal.StreamRecordConn
	for _, stage := range b.streamConcealPipeline().stages {
		switch stage {
		case concealStageRecord:
			if masquerade, ok := conceal.NewMasqueradeConn(conn, &b.bufferPool, b.masqueradeOpts); ok {
				recordConn = masquerade
				conn = masquerade
			}
		case concealStagePrelude:
			if prelude, ok := conceal.NewPreludeConn(recordConn, &b.bufferPool, b.framedOpts, b.preludeOpts); ok {
				conn = prelude
			}
		case concealStageFramed:
			if framed, ok := conceal.NewFramedConn(conn, &b.bufferPool, b.framedOpts); ok {
				conn = framed
			}
		}
	}
	return conn
}

func (b *BindStream) SetFramedOpts(opts conceal.FramedOpts) {
	b.framedOpts = opts
}

func (b *BindStream) SetPreludeOpts(opts conceal.PreludeOpts) {
	b.preludeOpts = opts
}

func (b *BindStream) SetMasqueradeOpts(opts conceal.MasqueradeOpts) {
	b.masqueradeOpts = opts
}

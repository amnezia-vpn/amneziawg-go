package conn

import (
	"errors"
	"sync"
)

var _ Bind = (*Multibind)(nil)

func NewMultibind(udp Bind, tcp Bind) *Multibind {
	return &Multibind{
		udp:    udp,
		tcp:    tcp,
		active: tcp,
	}
}

type Multibind struct {
	udp    Bind
	tcp    Bind
	active Bind
	mutex  sync.Mutex
}

func (mb *Multibind) SelectProto(proto string) error {
	mb.mutex.Lock()
	defer mb.mutex.Unlock()

	if proto == "udp" {
		mb.active = mb.udp
		return nil
	}

	if proto == "tcp" {
		mb.active = mb.tcp
		return nil
	}

	return errors.New("unknown protocol")
}

func (mb *Multibind) Proto() string {
	switch mb.active {
	case mb.tcp:
		return "tcp"
	case mb.udp:
		return "udp"
	}

	return "unknown"
}

func (mb *Multibind) Open(port uint16) (fns []ReceiveFunc, actualPort uint16, err error) {
	return mb.active.Open(port)
}

func (mb *Multibind) Close() error {
	return mb.active.Close()
}

func (mb *Multibind) SetMark(mark uint32) error {
	return mb.active.SetMark(mark)
}

func (mb *Multibind) Send(bufs [][]byte, ep Endpoint) error {
	return mb.active.Send(bufs, ep)
}

func (mb *Multibind) ParseEndpoint(s string) (Endpoint, error) {
	return mb.active.ParseEndpoint(s)
}

func (mb *Multibind) BatchSize() int {
	return mb.active.BatchSize()
}

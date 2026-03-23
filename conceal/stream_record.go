package conceal

import (
	"errors"
	"net"
)

var (
	ErrNoReadRecord  = errors.New("stream record reader unavailable")
	ErrNoWriteRecord = errors.New("stream record writer unavailable")
)

type StreamRecordConn interface {
	net.Conn
	CanReadRecord() bool
	CanWriteRecord() bool
	ReadRecord(b []byte) (int, error)
	WriteRecord(b []byte) (int, error)
}

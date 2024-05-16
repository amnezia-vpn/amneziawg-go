/*
 * Copyright (c) 2022. Proton AG
 *
 * This file is part of ProtonVPN.
 *
 * ProtonVPN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ProtonVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
 */

package conn

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	tls "github.com/refraction-networking/utls"
)

var lastErrorTimestamp time.Time

type StdNetBindTcp struct {
	mu sync.Mutex

	useTls        bool
	tcp           *net.TCPConn
	tls           *tls.UConn
	endpoint      *StdNetEndpoint
	currentPacket *bytes.Reader
	closed        bool
	log           *Logger
	errorChan     chan<- error
	protectSocket func(fd int) int

	tunsafe *TunSafeData
}

//goland:noinspection GoUnusedExportedFunction
func CreateStdNetBind(socketType string, log *Logger, errorChan chan<- error) Bind {
	if socketType == "udp" {
		return NewStdNetBind()
	} else {
		return &StdNetBindTcp{tunsafe: NewTunSafeData(), useTls: socketType == "tls", log: log, errorChan: errorChan}
	}
}

func (s *StdNetBindTcp) BatchSize() int {
	return 1
}

func (s *StdNetBindTcp) GetOffloadInfo() string {
	return ""
}

func (bind *StdNetBindTcp) ParseEndpoint(s string) (Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	if err == nil {
		bind.endpoint = &StdNetEndpoint{AddrPort: e}
	}
	if err != nil {
		return nil, err
	}
	return asEndpoint(e), err
}

func dialTcp(addr string, protectSocket func(fd int) int) (*net.TCPConn, int, error) {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	netConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, 0, err
	}

	conn := netConn.(*net.TCPConn)
	conn.SetLinger(0)

	// Retrieve port.
	laddr := conn.LocalAddr()
	taddr, err := net.ResolveTCPAddr(
		laddr.Network(),
		laddr.String(),
	)
	if err != nil {
		_ = conn.Close()
		return nil, 0, err
	}
	return conn, taddr.Port, nil
}

func (bind *StdNetBindTcp) upgradeToTls() error {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         randomServerName(),
	}

	conn := tls.UClient(bind.tcp, tlsConf, tls.HelloChrome_Auto)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	bind.log.Verbosef("TLS: Starting handshake")
	err := conn.Handshake()
	bind.log.Verbosef("TLS: Handshake result: %v", err)
	conn.SetDeadline(time.Time{})

	// On some devices (e.g. Samsung S21 FE) we see first WireGuard handshake failing on TLS socket and adding small
	// delay seems to fix that - issue is likely with timing on the server side, but couldn't find server-side fix.
	time.Sleep(100 * time.Millisecond)

	if err == nil {
		bind.tls = conn
	} else {
		bind.onSocketError(err)
		conn.Close()
	}
	return err
}

func (bind *StdNetBindTcp) Open(uport uint16) ([]ReceiveFunc, uint16, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	bind.log.Verbosef("TCP/TLS: Open %d", uport)
	bind.closed = false
	return []ReceiveFunc{bind.makeReceiveFunc()}, uport, nil
}

func (bind *StdNetBindTcp) initTcp() error {
	var err error

	if bind.tcp != nil {
		return ErrBindAlreadyOpen
	}

	var tcp *net.TCPConn

	tcp, _, err = dialTcp(bind.endpoint.DstToString(), bind.protectSocket)
	bind.log.Verbosef("TCP dial result: %v", err)
	if err != nil {
		bind.onSocketError(err)
		return err
	}
	bind.tcp = tcp
	return nil
}

func (bind *StdNetBindTcp) Close() error {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	bind.log.Verbosef("TCP/TLS: Close")
	bind.closed = true
	err := bind.closeInternal()
	return err
}

func (bind *StdNetBindTcp) closeInternal() error {
	var err error
	if bind.tls != nil {
		err = bind.tls.Close()
		bind.tls = nil
	}
	if bind.tcp != nil {
		err = bind.tcp.Close()
		bind.tcp = nil
	}
	bind.tunsafe.clear()
	return err
}

func (bind *StdNetBindTcp) getConn() (net.Conn, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	if bind.closed {
		return nil, net.ErrClosed
	}

	conn, err := bind.getConnInternal()
	if err != nil {
		bind.closed = true
	}
	return conn, err
}

func (bind *StdNetBindTcp) getConnInternal() (net.Conn, error) {
	if bind.tcp == nil {
		err := bind.initTcp()
		if err != nil {
			return nil, err
		}
	}
	if !bind.useTls {
		return bind.tcp, nil
	}
	if bind.tls == nil {
		err := bind.upgradeToTls()
		if err != nil {
			bind.closeInternal()
			return nil, err
		}
	}
	return bind.tls, nil
}

func (bind *StdNetBindTcp) makeReceiveFunc() ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []Endpoint) (int, error) {
		var err error
		eps[0] = bind.endpoint
		if bind.currentPacket == nil || bind.currentPacket.Len() == 0 {
			var conn net.Conn
			conn, err = bind.getConn()
			if err != nil {
				bind.logError("recv getConn", err)
				return 0, err
			}
			err = bind.readNextPacket(conn)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					bind.onSocketError(err)
					bind.logError("recv", err)
				}
				return 0, err
			}
		}
		n, err := bind.currentPacket.Read(packets[0])
		if err != nil {
			bind.logError("read packet", err)
			return 0, err
		}
		sizes[0] = n
		return 1, err
	}
}

func (bind *StdNetBindTcp) readNextPacket(conn net.Conn) error {
	tunSafeHeader := make([]byte, tunSafeHeaderSize)
	_, err := io.ReadFull(conn, tunSafeHeader)
	if err != nil {
		return err
	}

	tunSafeType, payloadSize := parseTunSafeHeader(tunSafeHeader)
	wgPacket, offset, err := bind.tunsafe.prepareWgPacket(tunSafeType, payloadSize)
	if err != nil {
		return err
	}

	_, err = io.ReadFull(conn, wgPacket[offset:])
	if err != nil {
		return err
	}

	bind.tunsafe.onRecvPacket(tunSafeType, wgPacket)
	bind.currentPacket = bytes.NewReader(wgPacket)
	return nil
}

func (bind *StdNetBindTcp) Send(buff [][]byte, endpoint Endpoint) error {
	conn, err := bind.getConn()
	if err != nil {
		bind.logError("send conn", err)
		return err
	}

	// As single tcp socket can send only to single destination. We assume endpoint passed to ParseEndpoint will be
	// the same.
	boundEndpoint := asEndpoint(bind.endpoint.AddrPort)
	if endpoint != boundEndpoint {
		return errors.New("StdNetBindTcp.Send endpoints mismatch")
	}
	for i := range buff {
		tunSafePacket := bind.tunsafe.wgToTunSafe(buff[i])
		_, err = conn.Write(tunSafePacket)
		if err != nil {
			bind.onSocketError(err)
			bind.logError("send", err)
			break
		}

	}
	return err
}

func (bind *StdNetBindTcp) SetMark(_ uint32) error {
	return nil
}

func (bind *StdNetBindTcp) onSocketError(err error) {
	if err != nil && !bind.closed {
		bind.errorChan <- err
	}
}

func (bind *StdNetBindTcp) logError(t string, err error) {
	if time.Now().After(lastErrorTimestamp.Add(5 * time.Second)) {
		lastErrorTimestamp = time.Now()
		bind.log.Errorf("TCP/TLS error %s: %v", t, err)
	}
}

// endpointPool contains a re-usable set of mapping from netip.AddrPort to Endpoint.
// This exists to reduce allocations: Putting a netip.AddrPort in an Endpoint allocates,
// but Endpoints are immutable, so we can re-use them.
var endpointPool = sync.Pool{
	New: func() any {
		return make(map[netip.AddrPort]Endpoint)
	},
}

// asEndpoint returns an Endpoint containing ap.
func asEndpoint(ap netip.AddrPort) Endpoint {
	m := endpointPool.Get().(map[netip.AddrPort]Endpoint)
	defer endpointPool.Put(m)
	e, ok := m[ap]
	if !ok {
		e = Endpoint(&StdNetEndpoint{AddrPort: ap})
		m[ap] = e
	}
	return e
}

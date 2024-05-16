// Package udp implements helper structures for working with UDP.
package udp

import (
	"errors"
	"net"
	"sync"
	"time"
)

// Listener is a struct that implements net.Listener interface for working
// with UDP. This is achieved by maintaining an internal "nat-like" table
// with destinations.
type Listener struct {
	conn *net.UDPConn

	// natTable is a table which maps peer addresses to udpConn structs.
	// Whenever a new packet is received, Listener looks up if there's
	// already a udpConn for the peer address and either creates a new one
	// or adds the packet to the existing one.
	natTable   map[string]*udpConn
	natTableMu sync.Mutex

	chanAccept chan *udpConn
	chanClosed chan struct{}

	closed   bool
	closedMu sync.Mutex
}

// Listen creates a new *Listener and is supposed to be a function similar
// to net.Listen, but for UDP only.
func Listen(network, addr string) (l *Listener, err error) {
	listenAddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, err
	}

	l = &Listener{
		natTable:   map[string]*udpConn{},
		chanAccept: make(chan *udpConn, 256),
		chanClosed: make(chan struct{}, 1),
	}

	l.conn, err = net.ListenUDP(network, listenAddr)
	if err != nil {
		return nil, err
	}

	go l.readLoop()

	return l, nil
}

// type check.
var _ net.Listener = (*Listener)(nil)

// Accept implements the net.Listener interface for *Listener.
func (l *Listener) Accept() (conn net.Conn, err error) {
	if l.isClosed() {
		return nil, net.ErrClosed
	}

	select {
	case conn = <-l.chanAccept:
		return conn, nil
	case <-l.chanClosed:
		return nil, net.ErrClosed
	}
}

// Close implements the net.Listener interface for *Listener.
func (l *Listener) Close() (err error) {
	if l.isClosed() {
		return nil
	}

	l.closedMu.Lock()
	l.closed = true
	l.closedMu.Unlock()

	close(l.chanClosed)

	l.natTableMu.Lock()
	for _, c := range l.natTable {
		log.OnCloserError(c, log.DEBUG)
	}
	l.natTableMu.Unlock()

	return l.conn.Close()
}

// Addr implements the net.Listener interface for *Listener.
func (l *Listener) Addr() (addr net.Addr) {
	return l.conn.LocalAddr()
}

// isClosed returns true if the listener is already closed.
func (l *Listener) isClosed() (ok bool) {
	l.closedMu.Lock()
	defer l.closedMu.Unlock()

	return l.closed
}

// readLoop implements the listener logic, it reads incoming data and passes it
// to the corresponding udpConn. When a new udpConn is created, it is written
// to the chanAccept channel.
func (l *Listener) readLoop() {
	buf := make([]byte, 65536)

	for !l.isClosed() {
		n, addr, err := l.conn.ReadFromUDP(buf)

		if err != nil || n == 0 {
			if errors.Is(err, net.ErrClosed) {
				return
			}

			// TODO(leninalive): Handle errors better here.

			continue
		}

		msg := make([]byte, n)
		copy(msg, buf[:n])
		l.acceptMsg(addr, msg)
	}
}

// acceptMsg passes the message to the corresponding udpConn.
func (l *Listener) acceptMsg(addr *net.UDPAddr, msg []byte) {
	l.natTableMu.Lock()
	defer l.natTableMu.Unlock()

	key := addr.String()
	conn, _ := l.natTable[key]
	if conn == nil || conn.isClosed() {
		conn = newUDPConn(addr, l.conn)
		l.natTable[key] = conn

		l.chanAccept <- conn
	}

	conn.addMsg(msg)
}

// udpConn represents a connection with a single peer.
type udpConn struct {
	peerAddr *net.UDPAddr
	conn     *net.UDPConn

	remaining []byte

	closed   bool
	closedMu sync.Mutex

	chanMsg    chan []byte
	chanClosed chan struct{}
}

// newUDPConn creates a new *udpConn for the specified peer.
func newUDPConn(peerAddr *net.UDPAddr, baseConn *net.UDPConn) (conn *udpConn) {
	return &udpConn{
		peerAddr:   peerAddr,
		conn:       baseConn,
		chanMsg:    make(chan []byte, 256),
		chanClosed: make(chan struct{}, 1),
	}
}

// addMsg adds a new byte array that can be then read from this connection.
func (c *udpConn) addMsg(b []byte) {
	c.chanMsg <- b
}

// isClosed returns true if the connection is closed.
func (c *udpConn) isClosed() (ok bool) {
	c.closedMu.Lock()
	defer c.closedMu.Unlock()

	return c.closed
}

// type check
var _ net.Conn = (*udpConn)(nil)

// Read implements the net.Conn interface for *udpConn.
func (c *udpConn) Read(b []byte) (n int, err error) {
	n = c.readRemaining(b)
	if n > 0 {
		return n, nil
	}

	select {
	case buf := <-c.chanMsg:
		c.remaining = buf
		n = c.readRemaining(b)

		return n, nil
	case <-c.chanClosed:
		return 0, net.ErrClosed
	}
}

// readRemaining reads remaining bytes that were not yet read.
func (c *udpConn) readRemaining(b []byte) (n int) {
	if c.remaining == nil || len(c.remaining) == 0 {
		return 0
	}

	if len(c.remaining) >= len(b) {
		n = len(b)

		copy(b, c.remaining[:n])
		c.remaining = c.remaining[n:]

		return n
	}

	n = len(c.remaining)

	copy(b[:n], c.remaining)
	c.remaining = nil

	return n
}

// Write implements the net.Conn interface for *udpConn.
func (c *udpConn) Write(b []byte) (n int, err error) {
	return c.conn.WriteToUDP(b, c.peerAddr)
}

// Close implements the net.Conn interface for *udpConn.
func (c *udpConn) Close() (err error) {
	c.closedMu.Lock()
	defer c.closedMu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	close(c.chanClosed)

	// Do not close the underlying UDP connection as it's shared with other
	// udpConn objects.

	return nil
}

// LocalAddr implements the net.Conn interface for *udpConn.
func (c *udpConn) LocalAddr() (addr net.Addr) {
	return c.conn.LocalAddr()
}

// RemoteAddr implements the net.Conn interface for *udpConn.
func (c *udpConn) RemoteAddr() (addr net.Addr) {
	return c.peerAddr
}

// SetDeadline implements the net.Conn interface for *udpConn.
func (c *udpConn) SetDeadline(_ time.Time) (err error) {
	// TODO(leninalive): Implement it.

	return nil
}

// SetReadDeadline implements the net.Conn interface for *udpConn.
func (c *udpConn) SetReadDeadline(_ time.Time) (err error) {
	// TODO(leninalive): Implement it.

	return nil
}

// SetWriteDeadline implements the net.Conn interface for *udpConn.
func (c *udpConn) SetWriteDeadline(_ time.Time) (err error) {
	// TODO(leninalive): Implement it.

	return nil
}

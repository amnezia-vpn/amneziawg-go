package conn

import (
	"errors"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/conceal"
	"golang.org/x/net/ipv4"
)

func fallbackTCPAddress(addr net.Addr, port uint16) string {
	host := "127.0.0.1"
	if tcpAddr, ok := addr.(*net.TCPAddr); ok && len(tcpAddr.IP) > 0 && tcpAddr.IP.To4() == nil {
		host = "::1"
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

func fallbackUDPAddress(addr net.Addr, port uint16) *net.UDPAddr {
	ip := net.IPv4(127, 0, 0, 1)
	if udpAddr, ok := addr.(*net.UDPAddr); ok && len(udpAddr.IP) > 0 && udpAddr.IP.To4() == nil {
		ip = net.IPv6loopback
	}
	return &net.UDPAddr{IP: ip, Port: int(port)}
}

func (b *BindStream) proxyStreamFallback(ep *streamEndpoint, first []byte) {
	rawConn := ep.rawConn
	if rawConn == nil {
		rawConn = ep.conn
	}
	if rawConn == nil {
		return
	}

	fallbackConn, err := b.dialer.DialContext(b.ctx, "tcp", fallbackTCPAddress(rawConn.RemoteAddr(), b.fallbackPort))
	if err != nil {
		ep.Close()
		return
	}

	if len(first) > 0 {
		if _, err := fallbackConn.Write(first); err != nil {
			fallbackConn.Close()
			ep.Close()
			return
		}
	}

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		_, _ = io.Copy(rawConn, fallbackConn)
		rawConn.Close()
		fallbackConn.Close()
	}()

	_, _ = io.Copy(fallbackConn, rawConn)
	rawConn.Close()
	fallbackConn.Close()
}

type fallbackUDPConn struct {
	UDPConn
	origin UDPConn
	port   uint16

	mu       sync.Mutex
	sessions map[string]*fallbackUDPSession
}

func newFallbackUDPConn(conn, origin UDPConn, port uint16) UDPConn {
	return &fallbackUDPConn{
		UDPConn:  conn,
		origin:   origin,
		port:     port,
		sessions: make(map[string]*fallbackUDPSession),
	}
}

func (c *fallbackUDPConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	for {
		n, oobn, flags, addr, err = c.UDPConn.ReadMsgUDP(b, oob)
		if err == nil {
			return n, oobn, flags, addr, nil
		}
		if !errors.Is(err, conceal.ErrFormat) || addr == nil {
			return n, oobn, flags, addr, err
		}
		if data := conceal.FormatErrorData(err); len(data) > 0 {
			_ = c.forward(addr, data)
		}
	}
}

func (c *fallbackUDPConn) Close() error {
	c.mu.Lock()
	for key, session := range c.sessions {
		session.close()
		delete(c.sessions, key)
	}
	c.mu.Unlock()
	return c.UDPConn.Close()
}

func (c *fallbackUDPConn) forward(remote *net.UDPAddr, data []byte) error {
	session, err := c.session(remote)
	if err != nil {
		return err
	}
	_, err = session.conn.Write(data)
	return err
}

func (c *fallbackUDPConn) session(remote *net.UDPAddr) (*fallbackUDPSession, error) {
	key := remote.String()

	c.mu.Lock()
	if session := c.sessions[key]; session != nil {
		c.mu.Unlock()
		return session, nil
	}
	c.mu.Unlock()

	fallbackConn, err := net.DialUDP("udp", nil, fallbackUDPAddress(remote, c.port))
	if err != nil {
		return nil, err
	}

	session := &fallbackUDPSession{
		parent: c,
		remote: &net.UDPAddr{
			IP:   append(net.IP(nil), remote.IP...),
			Port: remote.Port,
			Zone: remote.Zone,
		},
		conn: fallbackConn,
	}

	c.mu.Lock()
	if existing := c.sessions[key]; existing != nil {
		c.mu.Unlock()
		fallbackConn.Close()
		return existing, nil
	}
	c.sessions[key] = session
	c.mu.Unlock()

	go session.relay()
	return session, nil
}

func (c *fallbackUDPConn) removeSession(remote string) {
	c.mu.Lock()
	delete(c.sessions, remote)
	c.mu.Unlock()
}

type fallbackUDPSession struct {
	parent *fallbackUDPConn
	remote *net.UDPAddr
	conn   *net.UDPConn
	once   sync.Once
}

func (s *fallbackUDPSession) relay() {
	defer s.parent.removeSession(s.remote.String())
	buf := make([]byte, 65535)
	for {
		n, err := s.conn.Read(buf)
		if err != nil {
			return
		}
		_, _, _ = s.parent.origin.WriteMsgUDP(buf[:n], nil, s.remote)
	}
}

func (s *fallbackUDPSession) close() {
	s.once.Do(func() {
		s.conn.Close()
	})
}

type fallbackBatchConn struct {
	LinuxPacketConn
	origin LinuxPacketConn
	port   uint16

	mu       sync.Mutex
	sessions map[string]*fallbackBatchSession
}

type fallbackSessionCloser interface {
	closeFallbackSessions()
}

func newFallbackBatchConn(conn, origin LinuxPacketConn, port uint16) LinuxPacketConn {
	return &fallbackBatchConn{
		LinuxPacketConn: conn,
		origin:          origin,
		port:            port,
		sessions:        make(map[string]*fallbackBatchSession),
	}
}

func (c *fallbackBatchConn) ReadBatch(ms []ipv4.Message, flags int) (n int, err error) {
	for {
		n, err = c.LinuxPacketConn.ReadBatch(ms, flags)
		if err == nil {
			return n, nil
		}
		if !errors.Is(err, conceal.ErrFormat) {
			return n, err
		}
		data := conceal.FormatErrorData(err)
		remote := firstBatchUDPAddr(ms)
		if len(data) == 0 || remote == nil {
			return n, err
		}
		_ = c.forward(remote, data)
	}
}

func (c *fallbackBatchConn) closeFallbackSessions() {
	c.mu.Lock()
	for key, session := range c.sessions {
		session.close()
		delete(c.sessions, key)
	}
	c.mu.Unlock()
}

func (c *fallbackBatchConn) forward(remote *net.UDPAddr, data []byte) error {
	session, err := c.session(remote)
	if err != nil {
		return err
	}
	_, err = session.conn.Write(data)
	return err
}

func (c *fallbackBatchConn) session(remote *net.UDPAddr) (*fallbackBatchSession, error) {
	key := remote.String()

	c.mu.Lock()
	if session := c.sessions[key]; session != nil {
		c.mu.Unlock()
		return session, nil
	}
	c.mu.Unlock()

	fallbackConn, err := net.DialUDP("udp", nil, fallbackUDPAddress(remote, c.port))
	if err != nil {
		return nil, err
	}

	session := &fallbackBatchSession{
		parent: c,
		remote: &net.UDPAddr{
			IP:   append(net.IP(nil), remote.IP...),
			Port: remote.Port,
			Zone: remote.Zone,
		},
		conn: fallbackConn,
	}

	c.mu.Lock()
	if existing := c.sessions[key]; existing != nil {
		c.mu.Unlock()
		fallbackConn.Close()
		return existing, nil
	}
	c.sessions[key] = session
	c.mu.Unlock()

	go session.relay()
	return session, nil
}

func (c *fallbackBatchConn) removeSession(remote string) {
	c.mu.Lock()
	delete(c.sessions, remote)
	c.mu.Unlock()
}

type fallbackBatchSession struct {
	parent *fallbackBatchConn
	remote *net.UDPAddr
	conn   *net.UDPConn
	once   sync.Once
}

func (s *fallbackBatchSession) relay() {
	defer s.parent.removeSession(s.remote.String())
	buf := make([]byte, 65535)
	for {
		n, err := s.conn.Read(buf)
		if err != nil {
			return
		}
		msg := ipv4.Message{
			Buffers: [][]byte{buf[:n]},
			Addr:    s.remote,
		}
		_, _ = s.parent.origin.WriteBatch([]ipv4.Message{msg}, 0)
	}
}

func (s *fallbackBatchSession) close() {
	s.once.Do(func() {
		s.conn.Close()
	})
}

func firstBatchUDPAddr(ms []ipv4.Message) *net.UDPAddr {
	for i := range ms {
		if ms[i].N == 0 || ms[i].Addr == nil {
			continue
		}
		if addr, ok := ms[i].Addr.(*net.UDPAddr); ok {
			return addr
		}
	}
	return nil
}

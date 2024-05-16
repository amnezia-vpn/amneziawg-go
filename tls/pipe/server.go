// Package pipe implements the pipe logic, i.e. listening for TLS or UDP
// connections and proxying data to the target destination.
package pipe

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gobwas/ws"
	"github.com/amnezia-vpn/amneziawg-go/tls/tunnel"
	"github.com/amnezia-vpn/amneziawg-go/tls/udp"
	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

// defaultSNI is the default server name that will be used in both the client
// TLS ClientHello and the server's certificate when no TLS configuration is
// configured.
const defaultSNI = "example.org"

// upgradeTimeout is the read timeout for the first auth packet.
const upgradeTimeout = time.Second * 60

// Server represents an udptlspipe pipe. Depending on whether it is created in
// server- or client- mode, it listens to TLS or UDP connections and pipes the
// data to the destination.
type Server struct {
	listenAddr      string
	destinationAddr string
	dialer          proxy.Dialer
	serverMode      bool

	probeReverseProxyURL    string
	probeReverseProxyListen net.Listener

	// tlsConfig to use for TLS connections. In server mode it also has the
	// certificate that will be used.
	tlsConfig *tls.Config

	// password is a string that the server will search for in the first bytes.
	// If not found, the server will return a stub web page.
	password string

	// listen is the TLS listener for incoming connections
	listen net.Listener

	// srcConns is a set that is used to track active incoming TCP connections.
	srcConns   map[net.Conn]struct{}
	srcConnsMu *sync.Mutex

	// dstConns is a set that is used to track active connections to the proxy
	// destination.
	dstConns   map[net.Conn]struct{}
	dstConnsMu *sync.Mutex

	// Shutdown handling
	// --

	// lock protects started, tcpListener and udpListener.
	lock    sync.RWMutex
	started bool
	// wg tracks active workers. Stop won't finish until there is at least
	// won't finish until there's at least one active worker.
	wg sync.WaitGroup
}

// Config represents the server configuration.
type Config struct {
	// ListenAddr is the address (ip:port) where the server will be listening
	// to. Depending on the mode the server uses, it will either listen for TLS
	// or UDP connections.
	ListenAddr string

	// DestinationAddr is the address (host:port) to where the server will try
	// to connect. Depending on the mode the server uses, it will either
	// connect to a TLS endpoint (the pipe server) or not.
	DestinationAddr string

	// Password enables authentication of the pipe clients. If set, it also
	// enables active probing protection.
	Password string

	// ServerMode controls the way the pipe operates. When it's true, the pipe
	// server operates in server mode, i.e. it accepts incoming TLS connections
	// and proxies the data to the destination address over UDP. When it works
	// in client mode, it is the other way around: accepts UDP traffic and
	// proxies it to the destination pipe server over TLS.
	ServerMode bool

	// URL of a proxy server that can be used for proxying traffic to the
	// destination.
	ProxyURL string

	// VerifyCertificate enables server certificate verification in client mode.
	// If enabled, the client will verify the server certificate using the
	// system root certs store.
	VerifyCertificate bool

	// TLSServerName configures the server name to send in TLS ClientHello when
	// operating in client mode and the server name that will be used when
	// generating a stub certificate. If not set, the default domain name will
	// be used for these purposes.
	TLSServerName string

	// TLSCertificate is an optional field that allows to configure the TLS
	// certificate to use when running in server mode. This option makes sense
	// only for server mode. If not configured, the server will generate a stub
	// self-signed certificate automatically.
	TLSCertificate *tls.Certificate

	// ProbeReverseProxyURL is the URL that will be used by the reverse HTTP
	// proxy to respond to unauthorized or proxy requests. If not specified,
	// it will respond with a stub page 403 Forbidden.
	ProbeReverseProxyURL string
}

// createTLSConfig creates a TLS configuration as per the server configuration.
func createTLSConfig(config *Config) (tlsConfig *tls.Config, err error) {
	serverName := config.TLSServerName
	if serverName == "" {
		log.Info("TLS server name is not configured, using %s by default", defaultSNI)
		serverName = defaultSNI
	}

	if config.ServerMode {
		tlsCert := config.TLSCertificate
		if tlsCert == nil {
			log.Info("Generating a stub certificate for %s", serverName)
			tlsCert, err = createStubCertificate(serverName)
			if err != nil {
				return nil, fmt.Errorf("failed to generate a stub certificate: %w", err)
			}
		} else {
			log.Info("Using the supplied TLS certificate")
		}

		tlsConfig = &tls.Config{
			ServerName:   serverName,
			Certificates: []tls.Certificate{*tlsCert},
			MinVersion:   tls.VersionTLS12,
		}
	} else {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: !config.VerifyCertificate,
			ServerName:         serverName,
		}
	}

	return tlsConfig, nil
}

// NewServer creates a new instance of a *Server.
func NewServer(config *Config) (s *Server, err error) {
	s = &Server{
		listenAddr:           config.ListenAddr,
		destinationAddr:      config.DestinationAddr,
		password:             config.Password,
		probeReverseProxyURL: config.ProbeReverseProxyURL,
		dialer:               proxy.Direct,
		serverMode:           config.ServerMode,
		srcConns:             map[net.Conn]struct{}{},
		srcConnsMu:           &sync.Mutex{},
		dstConns:             map[net.Conn]struct{}{},
		dstConnsMu:           &sync.Mutex{},
	}

	s.tlsConfig, err = createTLSConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare TLS configuration: %w", err)
	}

	if config.ProxyURL != "" {
		var u *url.URL
		u, err = url.Parse(config.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}

		s.dialer, err = proxy.FromURL(u, s.dialer)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize proxy dialer: %w", err)
		}
	}

	return s, nil
}

// Addr returns the address the pipe listens to if it is started or nil.
func (s *Server) Addr() (addr net.Addr) {
	if s.listen == nil {
		return nil
	}

	return s.listen.Addr()
}

// Start starts the pipe, exits immediately if it failed to start
// listening.  Start returns once all servers are considered up.
func (s *Server) Start() (err error) {
	log.Info("Starting the server %s", s)

	s.lock.Lock()
	defer s.lock.Unlock()

	if s.started {
		return errors.New("Server is already started")
	}

	s.listen, err = s.createListener()
	if err != nil {
		return fmt.Errorf("failed to start pipe: %w", err)
	}

	if s.probeReverseProxyURL != "" {
		err = s.startProbeReverseProxy()
		if err != nil {
			return fmt.Errorf("failed to start probe reverse proxy: %w", err)
		}
	}

	s.wg.Add(1)
	go s.serve()

	s.started = true
	log.Info("Server has been started")

	return nil
}

// createListener creates a TLS listener in server mode and UDP listener in
// client mode.
func (s *Server) createListener() (l net.Listener, err error) {
	if s.serverMode {
		l, err = tls.Listen("tcp", s.listenAddr, s.tlsConfig)
		if err != nil {
			return nil, err
		}
	} else {
		l, err = udp.Listen("udp", s.listenAddr)
		if err != nil {
			return nil, err
		}
	}

	return l, nil
}

// startProbeReverseProxy starts a reverse HTTP proxy that will be used for
// answering unauthorized and probe requests. Returns the listener of that
// proxy. Original request URI will be appended to proxyURL.
func (s *Server) startProbeReverseProxy() (err error) {
	proxyURL := s.probeReverseProxyURL

	if _, err = url.Parse(proxyURL); err != nil {
		return fmt.Errorf("reverse proxy URL must be a valid URL: %w", err)
	}

	targetURL, err := url.Parse(s.probeReverseProxyURL)
	if err != nil {
		return fmt.Errorf("reverse proxy URL must be a valid URL: %w", err)
	}

	handler := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(targetURL)
			r.Out.Host = targetURL.Host
		},
	}

	srv := &http.Server{
		ReadHeaderTimeout: upgradeTimeout,
		Handler:           handler,
	}

	s.probeReverseProxyListen, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to start probe reverse proxy: %w", err)
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		log.Info("Starting probe reverse proxy")
		sErr := srv.Serve(s.probeReverseProxyListen)
		log.Info("Probe reverse proxy has been stopped due to: %v", sErr)
	}()

	return nil
}

// Shutdown stops the pipe and waits for all active connections to close.
func (s *Server) Shutdown(ctx context.Context) (err error) {
	log.Info("Stopping the server %s", s)

	s.stopServeLoop()

	// Closing the udpConn thread.
	log.OnCloserError(s.listen, log.DEBUG)

	if s.probeReverseProxyListen != nil {
		log.OnCloserError(s.probeReverseProxyListen, log.DEBUG)
	}

	// Closing active TCP connections.
	s.closeConnections(s.srcConnsMu, s.srcConns)

	// Closing active UDP connections.
	s.closeConnections(s.dstConnsMu, s.dstConns)

	// Wait until all worker threads finish working
	err = s.waitShutdown(ctx)

	log.Info("Server has been stopped")

	return err
}

// closeConnections closes all active connections.
func (s *Server) closeConnections(mu *sync.Mutex, conns map[net.Conn]struct{}) {
	mu.Lock()
	defer mu.Unlock()

	for c := range conns {
		_ = c.SetReadDeadline(time.Unix(1, 0))

		log.OnCloserError(c, log.DEBUG)
	}
}

// stopServeLoop sets the started flag to false thus stopping the serving loop.
func (s *Server) stopServeLoop() {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.started = false
}

// type check
var _ fmt.Stringer = (*Server)(nil)

// String implements the fmt.Stringer interface for *Server.
func (s *Server) String() (str string) {
	switch s.serverMode {
	case true:
		return fmt.Sprintf("tls://%s <-> udp://%s", s.listenAddr, s.destinationAddr)
	default:
		return fmt.Sprintf("udp://%s <-> tls://%s", s.listenAddr, s.destinationAddr)
	}
}

// serve implements the pipe logic, i.e. accepts new connections and tunnels
// data to the destination.
func (s *Server) serve() {
	defer s.wg.Done()
	defer log.OnPanicAndExit("serve", 1)

	defer log.OnCloserError(s.listen, log.DEBUG)

	for s.isStarted() {
		err := s.acceptConn()
		if err != nil {
			if !s.isStarted() {
				return
			}

			log.Error("exit serve loop due to: %v", err)

			return
		}
	}
}

// acceptConn accepts new incoming and tracks active connections.
func (s *Server) acceptConn() (err error) {
	conn, err := s.listen.Accept()
	if err != nil {
		// This type of errors should not lead to stopping the server.
		if errors.Is(os.ErrDeadlineExceeded, err) {
			return nil
		}

		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil
		}

		return err
	}

	log.Debug("Accepted new connection from %s", conn.RemoteAddr())

	s.saveSrcConn(conn)

	s.wg.Add(1)
	go s.serveConn(conn)

	return nil
}

// saveSrcConn tracks the connection to allow unblocking reads on shutdown.
func (s *Server) saveSrcConn(conn net.Conn) {
	s.srcConnsMu.Lock()
	defer s.srcConnsMu.Unlock()

	// Track the connection to allow unblocking reads on shutdown.
	s.srcConns[conn] = struct{}{}
}

// closeSrcConn closes the source connection and cleans up after it.
func (s *Server) closeSrcConn(conn net.Conn) {
	log.OnCloserError(conn, log.DEBUG)

	s.srcConnsMu.Lock()
	defer s.srcConnsMu.Unlock()

	delete(s.srcConns, conn)
}

// saveDstConn tracks the connection to allow unblocking reads on shutdown.
func (s *Server) saveDstConn(conn net.Conn) {
	s.dstConnsMu.Lock()
	defer s.dstConnsMu.Unlock()

	// Track the connection to allow unblocking reads on shutdown.
	s.dstConns[conn] = struct{}{}
}

// closeDstConn closes the destination connection and cleans up after it.
func (s *Server) closeDstConn(conn net.Conn) {
	// No destination connection opened yet, do nothing.
	if conn != nil {
		return
	}

	log.OnCloserError(conn, log.DEBUG)

	s.dstConnsMu.Lock()
	defer s.dstConnsMu.Unlock()

	delete(s.dstConns, conn)
}

// readWriteCloser is a helper object that's used for replacing
// io.ReadWriteCloser when the server peeked into the connection.
type readWriteCloser struct {
	io.Reader
	io.Writer
	io.Closer
}

// upgradeClientConn
func (s *Server) upgradeClientConn(conn net.Conn) (rwc io.ReadWriteCloser, err error) {
	log.Debug("Upgrading connection to %s", conn.RemoteAddr())

	// Give up to 60 seconds on the upgrade and authentication.
	_ = conn.SetReadDeadline(time.Now().Add(upgradeTimeout))
	defer func() {
		// Remove the deadline when it's not required any more.
		_ = conn.SetReadDeadline(time.Time{})
	}()

	u, err := url.Parse(fmt.Sprintf("wss://%s/?password=%s", s.tlsConfig.ServerName, s.password))
	if err != nil {
		return nil, err
	}

	var br *bufio.Reader
	br, _, err = ws.DefaultDialer.Upgrade(conn, u)
	if err != nil {
		return nil, fmt.Errorf("failed to upgrade: %w", err)
	}

	if br != nil && br.Buffered() > 0 {
		// If Upgrade returned a non-empty reader, then probably the server
		// immediately sent some data. This is not the expected behavior so
		// raise an error here.
		return nil, fmt.Errorf("received initial data len=%d from the server", br.Buffered())
	}

	return newWsConn(
		&readWriteCloser{
			Reader: conn,
			Writer: conn,
			Closer: conn,
		},
		conn.RemoteAddr(),
		ws.StateClientSide,
	), nil
}

// respondToProbe writes a dummy response to the client if it's not authorized
// or if it's a probe.
func (s *Server) respondToProbe(rwc io.ReadWriteCloser, req *http.Request) {
	if s.probeReverseProxyListen == nil {
		log.Debug("No probe reverse proxy configured, respond with a dummy 403 page")

		response := fmt.Sprintf("%s 403 Forbidden\r\n", req.Proto) +
			"Server: nginx\r\n" +
			fmt.Sprintf("Date: %s\r\n", time.Now().Format(http.TimeFormat)) +
			"Content-Type: text/html\r\n" +
			"Connection: close\r\n" +
			"\r\n" +
			"<html>\r\n" +
			"<head><title>403 Forbidden</title></head>\r\n" +
			"<center><h1>403 Forbidden</h1></center>\r\n" +
			"<hr><center>nginx</center>\r\n" +
			"</body>\r\n" +
			"</html>\r\n"

		_, _ = rwc.Write([]byte(response))

		return
	}

	log.Debug("Probe reverse proxy is configured, tunnel data to it")

	proxyConn, err := net.Dial("tcp", s.probeReverseProxyListen.Addr().String())
	if err != nil {
		log.Error("Failed to connect to the probe reverse proxy: %v", err)

		return
	}

	s.saveDstConn(proxyConn)

	tunnel.Tunnel("probeReverseProxy", rwc, proxyConn)
}

// upgradeServerConn attempts to upgrade the server connection and returns a
// rwc that wraps the original connection and can be used for tunneling data.
func (s *Server) upgradeServerConn(conn net.Conn) (rwc io.ReadWriteCloser, err error) {
	log.Debug("Upgrading connection from %s", conn.RemoteAddr())

	// Give up to 60 seconds on the upgrade and authentication.
	_ = conn.SetReadDeadline(time.Now().Add(upgradeTimeout))
	defer func() {
		// Remove the deadline when it's not required any more.
		_ = conn.SetReadDeadline(time.Time{})
	}()

	// bufio.Reader may read more than requested, so it's crucial to use
	// TeeReader so that we could restore the bytes that has been read.
	var buf bytes.Buffer
	r := bufio.NewReader(io.TeeReader(conn, &buf))

	req, err := http.ReadRequest(r)
	if err != nil {
		return nil, fmt.Errorf("cannot read HTTP request: %w", err)
	}

	// Now that authentication check has been done restore the peeked up data
	// so that it could be used further.
	originalRwc := &readWriteCloser{
		Reader: io.MultiReader(bytes.NewReader(buf.Bytes()), conn),
		Writer: conn,
		Closer: conn,
	}

	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		s.respondToProbe(originalRwc, req)

		return nil, fmt.Errorf("not a websocket")
	}

	clientPassword := req.URL.Query().Get("password")
	if s.password != "" && clientPassword != s.password {
		s.respondToProbe(originalRwc, req)

		return nil, fmt.Errorf("wrong password: %s", clientPassword)
	}

	_, err = ws.Upgrade(originalRwc)
	if err != nil {
		return nil, fmt.Errorf("failed to upgrade WebSocket: %w", err)
	}

	return newWsConn(originalRwc, conn.RemoteAddr(), ws.StateServerSide), nil
}

// serveConn processes incoming connection, authenticates it and proxies the
// data from it to the destination address.
func (s *Server) serveConn(conn net.Conn) {
	defer func() {
		s.wg.Done()

		s.closeSrcConn(conn)
	}()

	var rwc io.ReadWriteCloser = conn

	if s.serverMode {
		var err error
		rwc, err = s.upgradeServerConn(conn)
		if err != nil {
			log.Error("failed to accept server conn: %v", err)

			return
		}
	}

	s.processConn(rwc)
}

// processConn processes the prepared server connection that is passed as rwc.
func (s *Server) processConn(rwc io.ReadWriteCloser) {
	var dstConn net.Conn

	defer s.closeDstConn(dstConn)

	dstConn, err := s.dialDst()
	if err != nil {
		log.Error("failed to connect to %s: %v", s.destinationAddr, err)

		return
	}

	s.saveDstConn(dstConn)

	var dstRwc io.ReadWriteCloser = dstConn
	if !s.serverMode {
		dstRwc, err = s.upgradeClientConn(dstConn)
		if err != nil {
			log.Error("failed to upgrade: %v", err)

			return
		}
	}

	// Prepare ReadWriter objects for tunneling.
	var srcRw, dstRw io.ReadWriter
	srcRw = rwc
	dstRw = dstRwc

	// When the client communicates with the server it uses encoded messages so
	// connection between them needs to be wrapped. In server mode it is the
	// source connection, in client mode it is the destination connection.
	if s.serverMode {
		srcRw = tunnel.NewMsgReadWriter(srcRw)
	} else {
		dstRw = tunnel.NewMsgReadWriter(dstRw)
	}

	tunnel.Tunnel(s.String(), srcRw, dstRw)
}

// dialDst creates a connection to the destination. Depending on the mode the
// server operates in, it is either a TLS connection or a UDP connection.
func (s *Server) dialDst() (conn net.Conn, err error) {
	if s.serverMode {
		return s.dialer.Dial("udp", s.destinationAddr)
	}

	tcpConn, err := s.dialer.Dial("tcp", s.destinationAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to open connection to %s: %w", s.destinationAddr, err)
	}

	tlsConn := tls.UClient(tcpConn, s.tlsConfig, tls.HelloAndroid_11_OkHttp)

	err = tlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("cannot establish connection to %s: %w", s.destinationAddr, err)
	}

	return tlsConn, nil
}

// isStarted safely checks whether the pipe is started or not.
func (s *Server) isStarted() (started bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.started
}

// waitShutdown waits either until context deadline OR Server.wg.
func (s *Server) waitShutdown(ctx context.Context) (err error) {
	// Using this channel to wait until all goroutines finish their work.
	closed := make(chan struct{})
	go func() {
		defer log.OnPanic("waitShutdown")

		// Wait until all active workers finished its work.
		s.wg.Wait()
		close(closed)
	}()

	var ctxErr error
	select {
	case <-closed:
		// Do nothing here.
	case <-ctx.Done():
		ctxErr = ctx.Err()
	}

	return ctxErr
}

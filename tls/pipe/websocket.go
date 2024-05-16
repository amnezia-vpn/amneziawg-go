package pipe

import (
	"io"
	"net"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

// wsConn represents a WebSocket connection that's been already initialized.
type wsConn struct {
	rwc        io.ReadWriteCloser
	remoteAddr net.Addr
	r          *wsutil.Reader
	w          *wsutil.Writer
}

// newWsConn creates a wrapper over the existing network connection that is
// able to send/read messages using WebSocket protocol.
func newWsConn(rwc io.ReadWriteCloser, remoteAddr net.Addr, state ws.State) (c *wsConn) {
	r := wsutil.NewReader(rwc, state)
	w := wsutil.NewWriter(rwc, state, ws.OpBinary)

	return &wsConn{
		rwc:        rwc,
		remoteAddr: remoteAddr,
		r:          r,
		w:          w,
	}
}

// type check
var _ io.ReadWriteCloser = (*wsConn)(nil)

// Read implements the io.ReadWriteCloser interface for *wsConn.
func (w *wsConn) Read(b []byte) (n int, err error) {
	n, err = w.r.Read(b)
	if err == wsutil.ErrNoFrameAdvance {
		log.Debug("Reading the next WebSocket frame from %v", w.remoteAddr)

		hdr, fErr := w.r.NextFrame()
		if fErr != nil {
			return 0, io.EOF
		}

		log.Debug(
			"Received WebSocket frame with opcode=%d len=%d fin=%v from %v",
			hdr.OpCode,
			hdr.Length,
			hdr.Fin,
			w.remoteAddr,
		)

		// Reading again after the frame has been read.
		n, err = w.r.Read(b)

		// EOF in the case of wsutil.Reader does not mean that the connection is
		// closed, it only means that the current frame is finished.
		if err == io.EOF {
			err = nil
		}
	}

	return n, err
}

// Write implements the io.ReadWriteCloser interface for *wsConn.
func (w *wsConn) Write(b []byte) (n int, err error) {
	log.Debug("Writing data len=%d to the WebSocket %v", len(b), w.remoteAddr)

	n, err = w.w.Write(b)
	if err != nil {
		return 0, err
	}

	err = w.w.Flush()

	return n, err
}

// Close implements the io.ReadWriteCloser interface for *wsConn.
func (w *wsConn) Close() (err error) {
	return w.rwc.Close()
}

// Package tunnel implements the tunneling logic for copying data between two
// network connections both sides.
package tunnel

import (
	"fmt"
	"io"
	"sync"
)

// Tunnel passes data between two connections.
func Tunnel(pipeName string, left io.ReadWriter, right io.ReadWriter) {
	wg := &sync.WaitGroup{}
	wg.Add(2)

	go pipe(fmt.Sprintf("%s left->right", pipeName), left, right, wg)
	go pipe(fmt.Sprintf("%s left<-right", pipeName), right, left, wg)

	wg.Wait()
}

// pipe copies data from reader r to writer w.
func pipe(pipeName string, r io.Reader, w io.Writer, wg *sync.WaitGroup) {
	defer wg.Done()

	buf := make([]byte, 65536)
	var n int
	var err error

	for {
		n, err = r.Read(buf)

		if err != nil {
			log.Debug("failed to read: %v", err)

			return
		}

		if n == 0 {
			continue
		}

		log.Debug("%s: copying %d bytes", pipeName, n)

		_, err = w.Write(buf[:n])
		if err != nil {
			log.Debug("failed to write: %v", err)

			return
		}
	}
}

package device

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/chacha20"
)

// RelayPathMax is the maximum length of relay path data.
const RelayPathMax = 64

// Relay holds path data that the peer puts into the handshake initiation
// trailer. A relay reads it as ChaCha20(Key, packet[:12]) ^ packet[-TailSize():].
// The receiving peer must enable random_trailers to accept the tail.
type Relay struct {
	Key     HeaderCipherKey
	path    [RelayPathMax]byte // fixed size, so a copy of Relay owns its path
	pathLen uint8
}

// Path returns the path data.
func (r *Relay) Path() []byte {
	return r.path[:r.pathLen]
}

// TailSize returns the number of trailer bytes that hold the path data.
func (r *Relay) TailSize() int {
	if r == nil || r.Key.IsZero() {
		return 0
	}
	return int(r.pathLen)
}

// Seal writes the encrypted path to the end of packet.
func (r *Relay) Seal(packet []byte) error {
	n := r.TailSize()
	if n == 0 {
		return nil
	}
	cip, err := chacha20.NewUnauthenticatedCipher(r.Key[:], packet[:HeaderCipherNonceSize])
	if err != nil {
		return err
	}
	tail := packet[len(packet)-n:]
	cip.XORKeyStream(tail, r.Path())
	return nil
}

func (r *Relay) set(key, value string) error {
	switch key {
	case "relay_key":
		return r.Key.FromHex(value)
	case "relay_path":
		path, err := hex.DecodeString(value)
		if err != nil {
			return err
		}
		if len(path) > RelayPathMax {
			return fmt.Errorf("path is longer than %d bytes", RelayPathMax)
		}
		r.path = [RelayPathMax]byte{}            // cleanup
		r.pathLen = uint8(copy(r.path[:], path)) // copy and save size
	}
	return nil
}

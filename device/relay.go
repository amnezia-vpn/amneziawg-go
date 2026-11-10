package device

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"golang.org/x/crypto/chacha20"
)

// RelayPathMax is the maximum length of relay path data.
const RelayPathMax = 64

// Relay holds path data that the peer puts into the handshake initiation
// trailer. Seal zero-pads Path to PathSize. A relay reads it as
// ChaCha20(Key, packet[:12]) ^ packet[-TailSize():].
// The receiving peer must enable random_trailers to accept the tail.
type Relay struct {
	Key      HeaderCipherKey
	Path     []byte
	PathSize int
}

// TailSize returns the number of trailer bytes that hold the path data.
func (r *Relay) TailSize() int {
	if r == nil || r.Key.IsZero() {
		return 0
	}
	return r.paddedLen()
}

// paddedLen returns the length of Path zero-padded to PathSize.
func (r *Relay) paddedLen() int {
	if len(r.Path) == 0 {
		return 0
	}
	return max(r.PathSize, len(r.Path))
}

// Seal writes the zero-padded encrypted path to the end of packet.
func (r *Relay) Seal(packet []byte) error {
	n := r.TailSize()
	if n == 0 {
		return nil
	}
	cip, err := chacha20.NewUnauthenticatedCipher(r.Key[:], packet[:chacha20.NonceSize])
	if err != nil {
		return err
	}
	tail := packet[len(packet)-n:]
	copy(tail, r.Path)
	clear(tail[len(r.Path):])
	cip.XORKeyStream(tail, tail)
	return nil
}

func (r *Relay) set(key, value string) (err error) {
	switch key {
	case "relay_key":
		err = r.Key.FromHex(value)
	case "relay_path":
		if r.Path, err = hex.DecodeString(value); err == nil && len(r.Path) > RelayPathMax {
			err = fmt.Errorf("path is longer than %d bytes", RelayPathMax)
		}
	case "relay_path_size":
		var size uint64
		if size, err = strconv.ParseUint(value, 10, 0); err != nil {
			return
		}
		if size > RelayPathMax {
			return fmt.Errorf("size is larger than %d", RelayPathMax)
		}
		r.PathSize = int(size)
	}
	return
}

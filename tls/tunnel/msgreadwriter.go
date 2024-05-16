package tunnel

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

// MaxMessageLength is the maximum length that is safe to use.
// TODO(leninalive): Make it configurable.
const MaxMessageLength = 1320

// MinMessageLength is the minimum message size. If the message is smaller, it
// will be padded with random bytes.
const MinMessageLength = 100

// MaxPaddingLength is the maximum size of a random padding that's added to
// every message.
const MaxPaddingLength = 256

// MsgReadWriter is a wrapper over io.ReadWriter that encodes messages written
// to and read from the base writer.
type MsgReadWriter struct {
	base io.ReadWriter
}

// NewMsgReadWriter creates a new instance of *MsgReadWriter.
func NewMsgReadWriter(base io.ReadWriter) (rw *MsgReadWriter) {
	return &MsgReadWriter{base: base}
}

// type check
var _ io.ReadWriter = (*MsgReadWriter)(nil)

// Read implements the io.ReadWriter interface for *MsgReadWriter.
func (rw *MsgReadWriter) Read(b []byte) (n int, err error) {
	// Read the main message (always goes first).
	msg, err := readPrefixed(rw.base)
	if err != nil {
		return 0, err
	}

	// Skip padding.
	_, err = readPrefixed(rw.base)
	if err != nil {
		return 0, err
	}

	if len(b) < len(msg) {
		return 0, fmt.Errorf("message length %d is greater than the buffer size %d", len(msg), len(b))
	}

	copy(b[:len(msg)], msg)

	return len(msg), nil
}

// Write implements the io.ReadWriter interface for *MsgReadWriter.
func (rw *MsgReadWriter) Write(b []byte) (n int, err error) {
	// Create random padding to make it harder to understand what's inside
	// the tunnel.
	minLength := MinMessageLength - len(b)
	if minLength <= 0 {
		minLength = 1
	}
	maxLength := MaxPaddingLength
	if maxLength <= minLength {
		maxLength = minLength + 1
	}
	padding := createRandomPadding(minLength, maxLength)

	// Pack the message before sending it.
	msg := pack(b, padding)

	_, err = rw.base.Write(msg)

	if err != nil {
		return 0, err
	}

	return len(b), nil
}

// pack packs the message to be sent over the tunnel.
// Message looks like this:
//
// <2 bytes>: body length
// body
// <2 bytes>: padding length
// padding
func pack(b, padding []byte) (msg []byte) {
	msg = make([]byte, len(b)+len(padding)+4)

	binary.BigEndian.PutUint16(msg[:2], uint16(len(b)))
	copy(msg[2:], b)
	binary.BigEndian.PutUint16(msg[len(b)+2:len(b)+4], uint16(len(padding)))
	copy(msg[len(b)+4:], padding)

	return msg
}

// readPrefixed reads a 2-byte prefixed byte array from the reader.
func readPrefixed(r io.Reader) (b []byte, err error) {
	var length uint16
	err = binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}

	if length > MaxMessageLength {
		// Warn the user that this may not work correctly.
		log.Error(
			"Warning: received message of length %d larger than %d, considering reducing the MTU",
			length,
			MaxMessageLength,
		)
	}

	b = make([]byte, length)
	_, err = io.ReadFull(r, b)

	return b, err
}

// createRandomPadding creates a random padding array.
func createRandomPadding(minLength int, maxLength int) (b []byte) {
	// Generate a random length for the slice between minLength and maxLength.
	lengthBuf := make([]byte, 1)
	_, err := rand.Read(lengthBuf)
	if err != nil {
		log.Fatalf("Failed to use crypto/rand: %v", err)
	}
	length := int(lengthBuf[0])

	// Ensure the length is within our desired range.
	length = (length % (maxLength - minLength)) + minLength

	// Create a slice of the random length.
	b = make([]byte, length)

	// Fill the slice with random bytes.
	_, err = rand.Read(b)
	if err != nil {
		log.Fatalf("Failed to use crypto/rand: %v", err)
	}

	return b
}

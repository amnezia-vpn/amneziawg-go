package conceal

import (
	"encoding/binary"
	"io"
)

type StreamObfuscator struct {
}

func (c *StreamObfuscator) Read(reader io.Reader, buf []byte) (int, error) {
	var size uint32
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
		return 0, err
	}

	_, err := io.ReadFull(reader, buf[:size])
	return (int)(size), err
}

func (c *StreamObfuscator) Write(writer io.Writer, buf []byte) error {
	totalSize := len(buf) + 4

	pkt := buf
	if totalSize > cap(buf) {
		pkt = make([]byte, cap(buf)+4)
	}
	pkt = pkt[:totalSize]

	copy(pkt[4:], buf)

	size := uint32(len(buf))
	if _, err := binary.Encode(pkt[:4], binary.BigEndian, size); err != nil {
		return err
	}

	_, err := writer.Write(pkt)
	return err
}

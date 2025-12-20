package conceal

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode"
)

var (
	errInvalidData = errors.New("invalid data")
)

type readContext struct {
	*flexBuffer
	tmpPool      *BufferPool
	nextDataSize int
}

func (o *bytesObf) Read(reader io.Reader, ctx *readContext) error {
	tmp := ctx.tmpPool.GetBuffer()
	defer ctx.tmpPool.Put(tmp)

	buf := tmp[:len(o.data)]
	if _, err := io.ReadFull(reader, buf); err != nil {
		return err
	}

	if !bytes.Equal(buf, o.data) {
		return errInvalidData
	}

	return nil
}

func (o *dataObf) Read(reader io.Reader, ctx *readContext) error {
	buf := ctx.PushTail(ctx.nextDataSize)
	if buf == nil {
		return io.ErrShortBuffer
	}

	_, err := io.ReadFull(reader, buf)
	return err
}

func (o *dataSizeObf) Read(reader io.Reader, ctx *readContext) error {
	tmp := ctx.tmpPool.GetBuffer()
	defer ctx.tmpPool.Put(tmp)

	buf := tmp[:o.length]
	if _, err := io.ReadFull(reader, buf); err != nil {
		return err
	}

	var size int
	for _, b := range buf {
		size <<= 8
		size |= int(b)
	}
	ctx.nextDataSize = size

	return nil
}

func (o *dataStringObf) Read(reader io.Reader, ctx *readContext) error {
	tmp := ctx.tmpPool.GetBuffer()
	defer ctx.tmpPool.Put(tmp)

	base64len := base64.RawStdEncoding.EncodedLen(ctx.nextDataSize)
	buf := tmp[:base64len]
	if _, err := io.ReadFull(reader, buf); err != nil {
		return err
	}

	data := ctx.PushTail(ctx.nextDataSize)
	if data == nil {
		return io.ErrShortBuffer
	}

	if _, err := base64.RawStdEncoding.Decode(data, buf); err != nil {
		// return buf in case of error
		ctx.PullTail(len(data))
		return fmt.Errorf("failed to decode base64: %w", err)
	}

	return nil
}

func (o *randObf) Read(reader io.Reader, ctx *readContext) error {
	tmp := ctx.tmpPool.GetBuffer()
	defer ctx.tmpPool.Put(tmp)

	buf := tmp[:o.length]
	if _, err := io.ReadFull(reader, buf); err != nil {
		return err
	}

	// I guess, there is no way to validate randomness
	// so just return nil here like everything is fine
	return nil
}

func (o *randCharObf) Read(reader io.Reader, ctx *readContext) error {
	tmp := ctx.tmpPool.GetBuffer()
	defer ctx.tmpPool.Put(tmp)

	buf := tmp[:o.length]
	if _, err := io.ReadFull(reader, buf); err != nil {
		return err
	}

	for _, b := range buf {
		if !unicode.IsLetter(rune(b)) {
			return errInvalidData
		}
	}

	return nil
}

func (o *randDigitObf) Read(reader io.Reader, ctx *readContext) error {
	tmp := ctx.tmpPool.GetBuffer()
	defer ctx.tmpPool.Put(tmp)

	buf := tmp[:o.length]
	if _, err := io.ReadFull(reader, buf); err != nil {
		return err
	}

	for _, b := range buf {
		if !unicode.IsDigit(rune(b)) {
			return errInvalidData
		}
	}

	return nil
}

func (o *timestampObf) Read(reader io.Reader, ctx *readContext) error {
	var timestamp uint32
	if err := binary.Read(reader, binary.BigEndian, &timestamp); err != nil {
		return err
	}

	// TODO: check timestamp?

	return nil
}

package conceal

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"unicode"
)

var (
	errInvalidData = errors.New("invalid data")
)

type readContext struct {
	*flexBuffer
	nextDataSize int
}

func (o *bytesObf) Read(reader io.Reader, ctx *readContext) error {
	buf := ctx.TempBuffer(len(o.data))
	if buf == nil {
		return io.ErrShortBuffer
	}

	_, err := io.ReadFull(reader, buf)
	if err != nil {
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
	buf := ctx.TempBuffer(o.length)
	if buf == nil {
		return io.ErrShortBuffer
	}

	_, err := io.ReadFull(reader, buf)
	if err != nil {
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
	data := ctx.PushTail(ctx.nextDataSize)
	if data == nil {
		return io.ErrShortBuffer
	}

	base64len := base64.RawStdEncoding.EncodedLen(ctx.nextDataSize)
	buf := ctx.TempBuffer(base64len)
	if buf == nil {
		return io.ErrShortBuffer
	}

	if _, err := io.ReadFull(reader, buf); err != nil {
		return err
	}

	_, err := base64.RawStdEncoding.Decode(data, buf)
	return err
}

func (o *randObf) Read(reader io.Reader, ctx *readContext) error {
	buf := ctx.TempBuffer(o.length)
	if buf == nil {
		return io.ErrShortBuffer
	}

	_, err := io.ReadFull(reader, buf)
	return err
}

func (o *randCharObf) Read(reader io.Reader, ctx *readContext) error {
	buf := ctx.TempBuffer(o.length)
	if buf == nil {
		return io.ErrShortBuffer
	}

	_, err := io.ReadFull(reader, buf)
	if err != nil {
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
	buf := ctx.TempBuffer(o.length)
	if buf == nil {
		return io.ErrShortBuffer
	}

	_, err := io.ReadFull(reader, buf)
	if err != nil {
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

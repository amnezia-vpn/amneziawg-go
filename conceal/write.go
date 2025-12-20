package conceal

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"time"
)

type writeContext struct {
	*flexBuffer
}

func (o *bytesObf) Write(writer io.Writer, ctx *writeContext) error {
	_, err := writer.Write(o.data)
	return err
}

func (o *dataObf) Write(writer io.Writer, ctx *writeContext) error {
	buf := ctx.PullHead(-1)
	if buf == nil {
		return io.ErrShortBuffer
	}

	_, err := writer.Write(buf)
	return err
}

func (o *dataSizeObf) Write(writer io.Writer, ctx *writeContext) error {
	buf := ctx.TempBuffer(o.length)
	if buf == nil {
		return io.ErrShortBuffer
	}

	size := uint32(ctx.Len())
	for i := o.length - 1; i >= 0; i-- {
		buf[i] = byte(size & 0xFF)
		size >>= 8
	}

	_, err := writer.Write(buf)
	return err
}

func (o *dataStringObf) Write(writer io.Writer, ctx *writeContext) error {
	data := ctx.PullHead(-1)
	if data == nil {
		return io.ErrShortBuffer
	}

	base64len := base64.RawStdEncoding.EncodedLen(len(data))
	buf := ctx.TempBuffer(base64len)
	if buf == nil {
		return io.ErrShortBuffer
	}

	base64.RawStdEncoding.Encode(buf, data)

	_, err := writer.Write(buf)
	return err
}

func (o *randObf) Write(writer io.Writer, ctx *writeContext) error {
	buf := ctx.TempBuffer(o.length)
	if buf == nil {
		return io.ErrShortBuffer
	}

	rand.Read(buf)

	_, err := writer.Write(buf)
	return err
}

const chars52 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func (o *randCharObf) Write(writer io.Writer, ctx *writeContext) error {
	buf := ctx.TempBuffer(o.length)
	if buf == nil {
		return io.ErrShortBuffer
	}

	rand.Read(buf)
	for i := range buf {
		buf[i] = chars52[buf[i]%52]
	}

	_, err := writer.Write(buf)
	return err
}

const digits10 = "0123456789"

func (o *randDigitObf) Write(writer io.Writer, ctx *writeContext) error {
	buf := ctx.TempBuffer(o.length)
	if buf == nil {
		return io.ErrShortBuffer
	}

	rand.Read(buf)
	for i := range buf {
		buf[i] = digits10[buf[i]%10]
	}

	_, err := writer.Write(buf)
	return err
}

func (o *timestampObf) Write(writer io.Writer, ctx *writeContext) error {
	timestamp := uint32(time.Now().Unix())
	return binary.Write(writer, binary.BigEndian, timestamp)
}

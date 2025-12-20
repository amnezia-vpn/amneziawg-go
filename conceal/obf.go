package conceal

import (
	"io"
)

type Obf interface {
	Spec() string
	Read(reader io.Reader, ctx *readContext) error
	Write(writer io.Writer, ctx *writeContext) error
}

type Obfs []Obf

type timestampObf struct{}

type randDigitObf struct {
	length int
}

type randCharObf struct {
	length int
}

type randObf struct {
	length int
}

type dataSizeObf struct {
	length int
}

type dataObf struct {
}

type bytesObf struct {
	data []byte
}

type dataStringObf struct {
}

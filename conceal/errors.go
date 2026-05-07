package conceal

import (
	"bytes"
	"errors"
)

var ErrFormat = errors.New("conceal format error")

type FormatError struct {
	Data []byte
	Err  error
}

func NewFormatError(data []byte, err error) *FormatError {
	return &FormatError{
		Data: bytes.Clone(data),
		Err:  err,
	}
}

func (e *FormatError) Error() string {
	if e == nil {
		return ErrFormat.Error()
	}
	if e.Err == nil {
		return ErrFormat.Error()
	}
	return ErrFormat.Error() + ": " + e.Err.Error()
}

func (e *FormatError) Unwrap() []error {
	if e == nil || e.Err == nil {
		return []error{ErrFormat}
	}
	return []error{ErrFormat, e.Err}
}

func FormatErrorData(err error) []byte {
	var formatErr *FormatError
	if errors.As(err, &formatErr) {
		return bytes.Clone(formatErr.Data)
	}
	return nil
}

package conceal

import "io"

type sliceReader struct {
	buf []byte
}

func newSliceReader(buf []byte) sliceReader {
	return sliceReader{buf: buf}
}

func (r *sliceReader) Read(p []byte) (n int, err error) {
	if len(r.buf) == 0 {
		return 0, io.EOF
	}

	n = copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

type sliceWriter struct {
	buf []byte
}

func newSliceWriter(buf []byte) sliceWriter {
	return sliceWriter{buf: buf[:0]}
}

func (w *sliceWriter) Reset(buf []byte) {
	w.buf = buf[:0]
}

func (w *sliceWriter) Write(p []byte) (n int, err error) {
	w.buf = append(w.buf, p...)
	return len(p), nil
}

func (w *sliceWriter) Bytes() []byte {
	return w.buf
}

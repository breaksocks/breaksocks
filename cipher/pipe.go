package cipher

import (
	"bufio"
	"crypto/cipher"
	"io"
)

type StreamPipe struct {
	rw    io.ReadWriter
	buf_r bufio.Reader
	enc   cipher.Stream
	dec   cipher.Stream
}

func NewStreamPipe(rw io.ReadWriter) *StreamPipe {
	return &StreamPipe{rw: rw, buf_r: bufio.NewReader(rw)}
}

func (pipe *StreamPipe) SwitchCipher(enc, dec cipher.Stream) {
	pipe.enc, pipe.dec = enc, dec
}

func (pipe *StreamPipe) Read(bs []byte) (n, error) {
	if n, err := pipe.buf_r.Read(bs); err != nil {
		return 0, err
	} else {
		pipe.dec.XORKeyStream(bs, bs[:n])
		return n, nil
	}
}

func (pipe *StreamPipe) Write(bs []byte) (n, error) {
	pipe.enc.XORKeyStream(bs, bs)
	return rw.Write(bs)
}

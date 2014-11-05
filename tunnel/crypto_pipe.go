package tunnel

import (
	"bufio"
	"crypto/cipher"
	"io"
)

type StreamPipe struct {
	rw    io.ReadWriter
	buf_r *bufio.Reader
	enc   cipher.Stream
	dec   cipher.Stream
}

func NewStreamPipe(rw io.ReadWriter) *StreamPipe {
	return &StreamPipe{rw: rw, buf_r: bufio.NewReader(rw)}
}

func (pipe *StreamPipe) SwitchCipher(enc, dec cipher.Stream) {
	pipe.enc, pipe.dec = enc, dec
}

func (pipe *StreamPipe) Read(bs []byte) (int, error) {
	if n, err := pipe.buf_r.Read(bs); err == nil {
		if pipe.dec != nil {
			pipe.dec.XORKeyStream(bs, bs[:n])
		}
		return n, nil
	} else {
		return 0, err
	}
}

func (pipe *StreamPipe) Write(bs []byte) (int, error) {
	//fmt.Printf("send: %v\n", bs)
	if pipe.enc != nil {
		pipe.enc.XORKeyStream(bs, bs)
	}
	return pipe.rw.Write(bs)
}

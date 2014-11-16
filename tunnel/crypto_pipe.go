package tunnel

import (
	"bufio"
	"crypto/cipher"
	"io"
)

type StreamPipe struct {
	rw     io.ReadWriteCloser
	buf_r  *bufio.Reader
	enc    cipher.Stream
	dec    cipher.Stream
	closed bool
}

func NewStreamPipe(rw io.ReadWriteCloser) *StreamPipe {
	return &StreamPipe{rw: rw,
		buf_r:  bufio.NewReader(rw),
		closed: false}
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

func (pipe *StreamPipe) Close() error {
	if !pipe.closed {
		if err := pipe.rw.Close(); err != nil {
			return err
		}
		pipe.closed = true
	}
	return nil
}

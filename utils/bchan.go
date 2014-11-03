package utils

type BytesChan struct {
	Chan  chan []byte
	bytes [][]byte
	cur   int
	n     int
}

func NewBytesChan(n, size int, init_func func([]byte)) *BytesChan {
	bs := make([][]byte, n+1)
	for i := 0; i < n+1; i += 1 {
		bs[i] = make([]byte, size)
		if init_func != nil {
			init_func(bs[i])
		}
	}

	return &BytesChan{
		Chan:  make(chan []byte, n),
		bytes: bs,
		cur:   n,
		n:     n,
	}
}

func (bc *BytesChan) CurBytes() []byte {
	return bc.bytes[bc.cur]
}

func (bc *BytesChan) Send(size int) {
	bc.Chan <- bc.bytes[bc.cur][:size]
	bc.cur += 1
	if bc.cur == bc.n+1 {
		bc.cur = 0
	}
}

func (bc *BytesChan) Close() {
	close(bc.Chan)
}

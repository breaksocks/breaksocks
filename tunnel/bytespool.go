package tunnel

type BytesPool struct {
	ch               chan []byte
	size, block_size int
}

func NewBytesPool(size, block_size int) *BytesPool {
	ch := make(chan []byte, size)
	for i := 0; i < size; i += 1 {
		ch <- make([]byte, block_size)
	}
	return &BytesPool{ch: ch, size: size, block_size: block_size}
}

func (bp *BytesPool) Get() []byte {
	return <-bp.ch
}

func (bp *BytesPool) Put(bs []byte) {
	bp.ch <- bs
}

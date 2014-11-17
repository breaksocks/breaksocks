package tunnel

/*type BytesChan struct {*/
//Chan  chan []byte
//bytes [][]byte
//cur   int
//n     int
//}

//func NewBytesChan(n, size int, init_func func([]byte)) *BytesChan {
//bs := make([][]byte, n+1)
//for i := 0; i < n+1; i += 1 {
//bs[i] = make([]byte, size)
//if init_func != nil {
//init_func(bs[i])
//}
//}

//return &BytesChan{
//Chan:  make(chan []byte, n),
//bytes: bs,
//cur:   n,
//n:     n,
//}
//}

//func (bc *BytesChan) CurBytes() []byte {
//return bc.bytes[bc.cur]
//}

//func (bc *BytesChan) Send(size int) {
//bc.Chan <- bc.bytes[bc.cur][:size]
//bc.cur += 1
//if bc.cur == bc.n+1 {
//bc.cur = 0
//}
//}

//func (bc *BytesChan) Close() {
//close(bc.Chan)
//}

func WriteN2(bs []byte, offset int, n uint16) {
	bs[offset] = byte(n >> 8)
	bs[offset+1] = byte(n & 0xFF)
}

func ReadN2(bs []byte, offset int) uint16 {
	return (uint16(bs[offset]) << 8) | uint16(bs[offset+1])
}

func WriteN4(bs []byte, offset int, n uint32) {
	bs[offset] = byte(n >> 24)
	bs[offset+1] = byte(n >> 16)
	bs[offset+2] = byte(n >> 8)
	bs[offset+3] = byte(n)
}

func ReadN4(bs []byte, offset int) uint32 {
	var n uint32
	n |= uint32(bs[offset]) << 24
	n |= uint32(bs[offset+1]) << 16
	n |= uint32(bs[offset+2]) << 8
	n |= uint32(bs[offset+3])
	return n
}

/*func Dump(bs []byte) []byte {*/
//ret := make([]byte, len(bs))
//copy(ret, bs)
//return ret
/*}*/

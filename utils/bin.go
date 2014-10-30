package utils

func WriteN2(bs []byte, n uint16) {
	bs[0] = byte(n >> 8)
	bs[1] = byte(n & 0xFF)
}

func ReadN2(bs []byte) uint16 {
	return (uint16(bs[0]) << 8) | uint16(bs[1])
}

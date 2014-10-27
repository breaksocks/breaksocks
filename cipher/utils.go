package cipher

import (
	"crypto/md5"
)

func MakeCryptoKeyIV(password []byte, key_size, iv_size int) ([]byte, []byte) {
	buf := make([]byte, key_size+iv_size)

	for cur, remain, msum := 0, key_size+iv_size, ([]byte)(nil); remain > 0; {
		m := md5.New()
		if msum != nil {
			m.Write(msum)
		}

		msum = m.Sum(password)
		if len(msum) > remain {
			copy(buf[cur:], msum[:remain])
			remain = 0
		} else {
			copy(buf[cur:], msum)
			cur += len(msum)
			remain -= len(msum)
		}
	}

	key := buf[:key_size]
	iv := buf[key_size:]
	return key, iv
}

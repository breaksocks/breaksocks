package tunnel

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func TestKeyGen(t *testing.T) {
	start_t := time.Now()

	c1, _ := NewCipherContext(5)
	c2, _ := NewCipherContext(5)
	if c1 == nil || c2 == nil {
		t.Error("create ctx fail")
	}

	e, eerr := c1.MakeE()
	if eerr != nil {
		t.Error(eerr)
	}
	f, ferr := c2.MakeF()
	if ferr != nil {
		t.Error(ferr)
	}

	c1.CalcKey(f)
	c2.CalcKey(e)
	if c1.Key.Cmp(c2.Key) != 0 {
		t.Error("key not equal")
	}

	end_t := time.Now()
	delta := end_t.Sub(start_t)
	fmt.Println(delta)
}

func TestCipherEnc(t *testing.T) {
	cfg := GetCipherConfig("aes-128")
	if cfg == nil {
		t.Error("no such aes-128")
	}

	key, iv := MakeCryptoKeyIV([]byte("1234"), 16, 16)
	enc, dec, err := cfg.NewCipher(key, iv)
	if err != nil {
		t.Error(err)
	}

	msg := []byte("test message")
	right_enc := []byte{108, 242, 144, 18, 98, 87, 61, 91, 60, 179, 225, 189}
	bs := make([]byte, len(msg))
	dec_bs := make([]byte, len(msg))

	enc.XORKeyStream(bs, msg)
	if !bytes.Equal(bs, right_enc) {
		t.Error("encrypt error", bs, right_enc)
	}

	dec.XORKeyStream(dec_bs, bs)
	if string(dec_bs) != string(msg) {
		t.Error("dec fail")
	}
}

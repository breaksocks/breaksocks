package cipher

import (
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

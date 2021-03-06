package pow

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func TestThreadWork(t *testing.T) {
	s := Sha256Method{}
	r := bytes.NewReader([]byte("This is a test.  This is only a test. 123"))
	//                            0123456789012345
	//min := Sha256MinWork{uint64(0x00000FFFFFFFFFFF)}
	min := Sha256MinWork{uint64(0x0000FFFFFFFFFFFF)}
	starttime := time.Now()
	for i := 0; i < 10; i++ {
		d, w, er := ThreadWork(r, s, min, 10, nil)
		if er != nil {
			t.Error(er)
		}
		if d == nil {
			t.Errorf("digest is nil")
		}
		if w == nil {
			t.Errorf("proof of work is nil")
		}
		v, er2 := s.Verify(d, min, w)
		if er2 != nil {
			t.Error(er2)
		}
		if !v {
			t.Errorf("Work did not verify")
		}
	}
	donetime := time.Now()
	worktime := donetime.Sub(starttime)
	fmt.Printf("multithread time %s\n", worktime)
}

package pow

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func TestAllSha256(t *testing.T) {
	s := Sha256Method{}
	r := bytes.NewReader([]byte("This is a test.  This is only a test. 123"))
	d, _ := s.Digest(r)
	//                            0123456789012345
	//min := Sha256MinWork{uint64(0x00000FFFFFFFFFFF)}
	//min := Sha256MinWork{uint64(0x0FFFFFFFFFFFFFF)}
	min := Sha256MinWork{uint64(0x0000FFFFFFFFFFFF)}
	starttime := time.Now()
	for i := 0; i < 10; i++ {
		w, err := s.Work(d, min, nil)
		if err != nil {
			t.Error(err)
		}
		if w == nil {
			t.Error("work is nil")
		}
		v, err2 := s.Verify(d, min, w)
		if err2 != nil {
			t.Error(err2)
		}
		if !v {
			t.Errorf("Work did not verify")
		}
	}
	donetime := time.Now()
	worktime := donetime.Sub(starttime)
	fmt.Printf("single thread %s\n", worktime)
}

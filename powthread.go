package pow

import (
	"io"
	"sync"
)

//ThreadData a synchronized structure for multiple
//threads on the same data
type threadData struct {
	sync.Mutex
	data     io.Reader
	digest   DataDigest
	method   Method
	minwork  MinWork
	pow      Pow
	number   int
	complete bool
	err      error
	tquit    Quit
	donechan chan bool
}

func (t *threadData) done(pow Pow, e error) {
	t.Lock()
	defer t.Unlock()
	if t.complete {
		return
	}
	t.complete = true
	t.err = e
	t.pow = pow
}

func (t *threadData) Quit() bool {
	if t.tquit != nil {
		return t.complete || t.tquit.Quit()
	}
	return t.complete
}

func (t *threadData) work() (dig DataDigest, pow Pow, e error) {
	var err error
	t.digest, err = t.method.Digest(t.data)
	if err != nil {
		return nil, nil, err
	}
	for i := 0; i < t.number; i++ {
		go func() {
			pw, err := t.method.Work(t.digest, t.minwork, t)
			t.done(pw, err)
			t.donechan <- true
		}()
	}
	<-t.donechan
	return t.digest, t.pow, t.err
}

//ThreadWork starts multiple goroutines to generate proof of work
func ThreadWork(data io.Reader, method Method, minwork MinWork, numthread int, quit Quit) (dig DataDigest, pow Pow, e error) {
	td := threadData{data: data, method: method, minwork: minwork, number: numthread, tquit: quit, donechan: make(chan bool)}
	return td.work()
}

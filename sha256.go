package pow

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/pkg/errors"
)

//Sha256MinWork specifies the minimum work required for
//the Sha256Method.
type Sha256MinWork struct {
	Min uint64
}

//Sha256Digest contains the sha256 hash of some input data
type Sha256Digest struct {
	Digest []byte
}

//Sha256Method implements a proof-of-work method using sha256.
type Sha256Method struct {
}

//Sha256Pow represents the proof-of-work for the Sha256Method
type Sha256Pow struct {
	Proof uint64
}

//Name returns the name of this method "Sha256"
func (s Sha256Method) Name() string {
	return "Sha256"
}

//Digest uses sha256 to digest the given input data
func (s Sha256Method) Digest(data io.Reader) (dig DataDigest, e error) {
	sha256 := sha256.New()
	_, err := io.Copy(sha256, data)
	if err != nil {
		return nil, err
	}
	return Sha256Digest{sha256.Sum(nil)}, nil
}

func (s *Sha256Method) getValue(dig *Sha256Digest) uint64 {
	return binary.BigEndian.Uint64(dig.Digest)
}

//Work implements the Work function for the Method interface
func (s Sha256Method) Work(data DataDigest, minwork MinWork, quit Quit) (pow Pow, e error) {
	shadig := data.(Sha256Digest)
	shamin := minwork.(Sha256MinWork)
	sha256 := sha256.New()
	proofbuf := make([]byte, 8)
	_, err := io.ReadFull(rand.Reader, proofbuf)
	if err != nil {
		return nil, err
	}
	proofvalue := binary.BigEndian.Uint64(proofbuf)
	buf := make([]byte, 16)
	copy(buf, shadig.Digest)
	binary.BigEndian.PutUint64(buf[8:], proofvalue)
	sha256.Write(buf)
	tv := binary.BigEndian.Uint64(sha256.Sum(nil))
	q := false
	if quit != nil {
		q = quit.Quit()
	}
	for tv > shamin.Min && !q {
		proofvalue++
		sha256.Reset()
		binary.BigEndian.PutUint64(buf[8:], proofvalue)
		sha256.Write(buf)
		tv = binary.BigEndian.Uint64(sha256.Sum(nil))
		if quit != nil {
			q = quit.Quit()
		}
	}
	if q {
		return nil, errors.Errorf("Proof of work quit prematurely")
	}
	return Sha256Pow{proofvalue}, nil
}

//Verify tests if the pow meets the minwork required
func (s Sha256Method) Verify(dig DataDigest, minwork MinWork, pow Pow) (bool, error) {
	shadig := dig.(Sha256Digest)
	shamin := minwork.(Sha256MinWork)
	shapow := pow.(Sha256Pow)
	sha256 := sha256.New()
	buf := make([]byte, 16)
	copy(buf, shadig.Digest)
	binary.BigEndian.PutUint64(buf[8:], shapow.Proof)
	sha256.Write(buf)
	tv := binary.BigEndian.Uint64(sha256.Sum(nil))
	return tv <= shamin.Min, nil
}

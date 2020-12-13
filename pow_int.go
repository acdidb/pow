package pow

import "io"

//MinWork defines minimum work required for a
//proof of work method
type MinWork interface{}

//DataDigest defines a representation of the data to do work on and
//verify proof-of-work against - usually a hash/digest
type DataDigest interface{}

//Pow shows proof of work for some input data
type Pow interface{}

//Quit tells us to stop working
type Quit interface {
	Quit() bool
}

//Method specifies a proof-of-work method and provides
//functions to do the work and verify it.
//All implementations must be thread safe
type Method interface {
	//Name returns the unique name for this proof of work method
	Name() string
	Digest(data io.Reader) (DataDigest, error)
	//Work does the minimum work specified by MinWork for the input dig.
	//It returns the proof-of-work Pow or an error if there were issues reading
	//the data
	Work(dig DataDigest, minwork MinWork, quit Quit) (Pow, error)
	//Verifies the minimum work, specified by MinWork, has been done to produce
	//Pow on the input dig.  Returns a bool that is true if the required minimum
	//work has been done, or an error if there were issues reading the data.
	Verify(dig DataDigest, minwork MinWork, pow Pow) (bool, error)
}

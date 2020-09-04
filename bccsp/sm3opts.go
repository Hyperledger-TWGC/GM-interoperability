package bccsp



// SHAOpts contains options for computing SHA.
type SM3Opts struct {
}

// Algorithm returns the hash algorithm identifier (to be used).
func (opts *SM3Opts) Algorithm() string {
	return SM3
}


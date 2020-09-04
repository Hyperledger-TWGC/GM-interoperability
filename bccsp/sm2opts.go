package bccsp


//SM2KeyGenOpts contains options for SM2 key generation
type SM2KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SM2KeyGenOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
func (opts *SM2KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}


// ECDSAReRandKeyOpts contains options for ECDSA key re-randomization.
type SM2ReRandKeyOpts struct {
	Temporary bool
	Expansion []byte
}

// Algorithm returns the key derivation algorithm identifier (to be used).
func (opts *SM2ReRandKeyOpts) Algorithm() string {
	return SM2ReRand
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2ReRandKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

// ExpansionValue returns the re-randomization factor
func (opts *SM2ReRandKeyOpts) ExpansionValue() []byte {
	return opts.Expansion
}

// SM2PKIXPublicKeyImportOpts contains options for SM2 public key importation in PKIX format
type SM2PKIXPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SM2PKIXPublicKeyImportOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2PKIXPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// SM2PrivateKeyImportOpts contains options for SM2 secret key importation in DER format
// or PKCS#8 format.
type SM2PrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SM2PrivateKeyImportOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// SM2GoPublicKeyImportOpts contains options for SM2 key importation from ecdsa.PublicKey
type SM2GoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SM2GoPublicKeyImportOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2GoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}


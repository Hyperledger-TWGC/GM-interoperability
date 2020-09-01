package bccsp


const (

	SM4 = "SM4"

	SM3 = "SM3"

	SM2 = "SM2"

	SM2ReRand="SM2ReRand"

	// HMACTruncated256 HMAC truncated at 256 bits.
	HMACTruncated256 = "HMAC_TRUNCATED_256"

	// HMAC keyed-hash message authentication code
	HMAC = "HMAC"

	// X509Certificate Label for X509 certificate related operation
	X509Certificate = "X509Certificate"
)


// HMACTruncated256SM4DeriveKeyOpts contains options for HMAC truncated
// at 256 bits key derivation.
type HMACTruncated256SM4DeriveKeyOpts struct {
	Temporary bool
	Arg       []byte
}

// Algorithm returns the key derivation algorithm identifier (to be used).
func (opts *HMACTruncated256SM4DeriveKeyOpts) Algorithm() string {
	return HMACTruncated256
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *HMACTruncated256SM4DeriveKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

// Argument returns the argument to be passed to the HMAC
func (opts *HMACTruncated256SM4DeriveKeyOpts) Argument() []byte {
	return opts.Arg
}

// HMACDeriveKeyOpts contains options for HMAC key derivation.
type HMACDeriveKeyOpts struct {
	Temporary bool
	Arg       []byte
}

// Algorithm returns the key derivation algorithm identifier (to be used).
func (opts *HMACDeriveKeyOpts) Algorithm() string {
	return HMAC
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *HMACDeriveKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

// Argument returns the argument to be passed to the HMAC
func (opts *HMACDeriveKeyOpts) Argument() []byte {
	return opts.Arg
}


// X509PublicKeyImportOpts contains options for importing public keys from an x509 certificate
type X509PublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *X509PublicKeyImportOpts) Algorithm() string {
	return X509Certificate
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *X509PublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

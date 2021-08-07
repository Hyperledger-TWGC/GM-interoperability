package gmkeys

type SM2Privatekey struct {
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *SM2Privatekey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *SM2Privatekey) Private() bool {
	return true
}

type SM2Publickey struct {
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (k *SM2Publickey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *SM2Publickey) Private() bool {
	return false
}

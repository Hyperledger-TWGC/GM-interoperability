package gmssl

import (
	. "github.com/Hyperledger-TWGC/pku-gm/gmssl"
	. "github.com/hyperledger/fabric/bccsp"
	. "hash"
	"strings"
)

// SM2PrivateKey
type SM2PrivateKey struct {
	*PrivateKey
	Password string
	skiHash  Hash
}

func (p *SM2PrivateKey) Bytes() ([]byte, error) {
	pem, err := p.GetPEM(SMS4, p.Password)
	return []byte(pem), err
}
func (p *SM2PrivateKey) Symmetric() bool {
	return false
}
func (p *SM2PrivateKey) Private() bool {
	return true
}

func (p *SM2PrivateKey) PublicKey() (Key, error) {
	publicKey, err := p.GetPublicKey()
	if err != nil {
		return nil, err
	}

	return &SM2PublicKey{Key: publicKey}, nil
}
func (p *SM2PrivateKey) SKI() []byte {
	text, err := p.GetText()
	PanicError(err)
	p.skiHash.Reset()
	p.skiHash.Write([]byte(text))
	sum := p.skiHash.Sum(nil)
	p.skiHash.Reset()
	return sum
}

// SM2PublicKey
type SM2PublicKey struct {
	Key     *PublicKey
	skiHash Hash
}

func (p *SM2PublicKey) Bytes() ([]byte, error) {
	pem, err := p.Key.GetPEM()
	return []byte(pem), err
}
func (p *SM2PublicKey) SKI() []byte {

	text, err := p.Key.GetText()
	PanicError(err)
	p.skiHash.Reset()
	p.skiHash.Write([]byte(text))
	sum := p.skiHash.Sum(nil)
	p.skiHash.Reset()
	return sum
}

func (p *SM2PublicKey) Symmetric() bool {
	return false
}
func (p *SM2PublicKey) Private() bool {
	return false
}
func (p *SM2PublicKey) PublicKey() (Key, error) {
	return p, nil
}

// Software-based GM Suite
type GMSWSuite struct {
	KeyStore
}

// KeyGen generates a Key using opts. FIXME logic correct?
func (s *GMSWSuite) KeyGen(opts KeyGenOpts) (k Key, err error) {
	var algorithm = opts.Algorithm()

	// fall to default
	if algorithm == "" {
		algorithm = "sm2p256v1"
	}
	sm2keygenargs := [][2]string{
		{"ec_paramgen_curve", algorithm},
		{"ec_param_enc", "named_curve"},
	}
	// TODO factory to support multiple Key type
	sm2sk, err := GeneratePrivateKey("EC", sm2keygenargs, nil)
	if !opts.Ephemeral() {
		// Store the Key
		err = s.StoreKey(k)
		if err != nil {
			return nil, err
		}
	}
	sm3 := New()
	return &SM2PrivateKey{PrivateKey: sm2sk, skiHash: sm3}, nil
}

// KeyDeriv derives a Key from k using opts.
// The opts argument should be appropriate for the primitive used.
func (s *GMSWSuite) KeyDeriv(k Key, opts KeyDerivOpts) (dk Key, err error) {
	panic("To be Implement") // TODO
}

// KeyImport imports a Key from its raw representation using opts.
// The opts argument should be appropriate for the primitive used.
func (s *GMSWSuite) KeyImport(raw interface{}, opts KeyImportOpts) (k Key, err error) {
	var algo = opts.Algorithm()

	var pem = raw.(string)

	var sm3 = New()
	// TODO do not use switch
	if strings.Contains(strings.ToLower(algo), "pub") {
		pubkey, err := NewPublicKeyFromPEM(pem)
		if err != nil {
			return nil, err
		}
		k = &SM2PublicKey{
			Key: pubkey,
			skiHash: sm3,
		}
	} else {
		privKey, err := NewPrivateKeyFromPEM(pem, "") // TODO password support
		if err != nil {
			return nil, err
		}
		k = &SM2PrivateKey{
			PrivateKey: privKey,
			skiHash: sm3,
		}
	}
	if !opts.Ephemeral() {
		// Store the Key
		err = s.StoreKey(k)
		if err != nil {
			return nil, err
		}
	}
	return
}

// GetKey returns the Key this CSP associates to
// the Subject Key Identifier ski.
func (s *GMSWSuite) GetKey(ski []byte) (k Key, err error) {
	k, err = s.KeyStore.GetKey(ski)
	return
}

// Hash hashes messages msg using options opts.
// If opts is nil, the default hash function will be used.
func (s *GMSWSuite) Hash(msg []byte, opts HashOpts) (hash []byte, err error) {
	hashAlgo, err := s.GetHash(opts)
	if err != nil {
		return nil, err
	}
	hashAlgo.Reset()
	hashAlgo.Write(msg)
	hash = hashAlgo.Sum(nil)
	hashAlgo.Reset()
	return
}

// GetHash returns and instance of hash.Hash using options opts.
// If opts is nil, the default hash function will be returned.
func (s *GMSWSuite) GetHash(opts HashOpts) (h Hash, err error) {
	sm3 := New()
	return sm3, nil
}

// Sign signs digest using Key k.
// The opts argument should be appropriate for the algorithm used.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest).
func (s *GMSWSuite) Sign(k Key, digest []byte, opts SignerOpts) (signature []byte, err error) {
	sm2PrivK := k.(*SM2PrivateKey)
	signature, err = sm2PrivK.Sign("sm2sign", digest, nil)
	return
}

// Verify verifies signature against Key k and digest
// The opts argument should be appropriate for the algorithm used.
func (s *GMSWSuite) Verify(k Key, signature, digest []byte, opts SignerOpts) (valid bool, err error) {
	sm2PubK := k.(*SM2PublicKey)
	err = sm2PubK.Key.Verify("sm2sign", digest, signature, nil)
	return err == nil, err
}

// Encrypt encrypts plaintext using Key k.
// The opts argument should be appropriate for the algorithm used.
func (s *GMSWSuite) Encrypt(k Key, plaintext []byte, opts EncrypterOpts) (ciphertext []byte, err error) {
	sm2PubK := k.(*SM2PublicKey)
	ciphertext, err = sm2PubK.Key.Encrypt("sm2encrypt-with-sm3", plaintext, nil)
	return
}

// Decrypt decrypts ciphertext using Key k.
// The opts argument should be appropriate for the algorithm used.
func (s *GMSWSuite) Decrypt(k Key, ciphertext []byte, opts DecrypterOpts) (plaintext []byte, err error) {
	sm2PrivK := k.(*SM2PrivateKey)
	plaintext, err = sm2PrivK.Decrypt("sm2encrypt-with-sm3", ciphertext, nil)
	return
}

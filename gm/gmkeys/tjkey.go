package gmkeys

import (
	"crypto/elliptic"

	tj "github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	tjsm3 "github.com/Hyperledger-TWGC/tjfoc-gm/sm3"
	tjx509 "github.com/Hyperledger-TWGC/tjfoc-gm/x509"

	"github.com/hyperledger/fabric/bccsp"
)

type TJSM2Publickey struct {
	SM2Publickey
	Key *tj.PublicKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *TJSM2Publickey) Bytes() ([]byte, error) {
	//pem
	return tjx509.WritePublicKeyToPem(k.Key)
}

// SKI returns the subject key identifier of this key.
func (k *TJSM2Publickey) SKI() []byte {
	//hash for text
	if k.Key == nil {
		return nil
	}

	//Marshall the public key
	raw := elliptic.Marshal(k.Key.Curve, k.Key.X, k.Key.Y)

	// Hash it
	return tjsm3.Sm3Sum(raw)
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *TJSM2Publickey) PublicKey() (bccsp.Key, error) {
	return k, nil
}

type TJSM2PrivateKey struct {
	SM2Privatekey
	Key *tj.PrivateKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *TJSM2PrivateKey) Bytes() ([]byte, error) {
	//pem
	return tjx509.WritePrivateKeyToPem(k.Key, nil)
}

// SKI returns the subject key identifier of this key.
func (k *TJSM2PrivateKey) SKI() []byte {
	//hash for text
	if k.Key == nil {
		return nil
	}

	//Marshall the public key
	raw := elliptic.Marshal(k.Key.Curve, k.Key.PublicKey.X, k.Key.PublicKey.Y)

	// Hash it
	return tjsm3.Sm3Sum(raw)
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *TJSM2PrivateKey) PublicKey() (bccsp.Key, error) {
	//public key
	return &TJSM2Publickey{
		Key: &k.Key.PublicKey,
	}, nil
}

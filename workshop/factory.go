package workshop

import (
	"io/ioutil"

	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
)

var TJ = "TJ"
var PKU = "PKU"
var CCS = "CCS"

func GenerateSM2Instance(sourceDef string) (SM2, error) {
	if sourceDef == TJ {
		return NewTJSM2()
	}
	if sourceDef == CCS {
		return NewCCSSM2()
	}
	return nil, nil
}

func ReadFile(filename string) ([]byte, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return content, nil
}

func LoadFromPriPem(file string) (SM2, error) {
	privKeyPem, err := ReadFile(file)
	if err != nil {
		return nil, err
	}
	privKey, err := x509.ReadPrivateKeyFromPem(privKeyPem, nil)
	if err != nil {
		return nil, err
	}
	return &TJSM2{PrivateKey: privKey, PublicKey: &privKey.PublicKey}, nil
}

func LoadFromPubPem(file string) (SM2, error) {
	pubKeyPem, err := ReadFile(file)
	if err != nil {
		return nil, err
	}
	pubkey, err := x509.ReadPublicKeyFromPem(pubKeyPem)
	if err != nil {
		return nil, err
	}
	return &TJSM2{PrivateKey: nil, PublicKey: pubkey}, nil
}

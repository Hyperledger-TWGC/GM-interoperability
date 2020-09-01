package main

import (
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"testing"
)

func TestLoadFromPKUGM(t *testing.T) {
	privKeyPem := ReadFile("privateKey.pku.pem", t)
	_, err := x509.ReadPrivateKeyFromPem([]byte(privKeyPem), nil)
	Fatal(err, t)
}

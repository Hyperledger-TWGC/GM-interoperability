package main

import "testing"
import "github.com/Hyperledger-TWGC/pku-gm/gmssl"

func TestPKUSM2KeyPemImport(t *testing.T) {
	var privKeyPem = "privateKey.tjfoc.pem"
	pemBytes := ReadFile(privKeyPem, t)
	_, err := gmssl.NewPrivateKeyFromPEM(string(pemBytes), "")
	Fatal(err, t)
}

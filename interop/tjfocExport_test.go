package main

import (
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"testing"
)

func TestTJSM2Pem(t *testing.T) {
	sm2PrivKey, err := sm2.GenerateKey(nil)
	Fatal(err, t)
	pemBytes, err := x509.WritePrivateKeytoPem(sm2PrivKey, nil)
	Fatal(err, t)
	var pemFile = "privateKey.tjfoc.pem"
	WriteFile(pemBytes, pemFile, t)

}

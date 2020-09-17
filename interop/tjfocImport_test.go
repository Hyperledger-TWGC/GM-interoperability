package interop

import (
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"testing"
)

func TestLoadSM2PrivateFromPEM(t *testing.T) {
	privKeyPem := ReadFile("testdata/privateKey.pku.pem", t)
	_, err := x509.ReadPrivateKeyFromPem(privKeyPem, nil)
	Fatal(err, t)

	pemBytes2 := ReadFile("testdata/privateKey.ccs.pem", t)
	_, err = x509.ReadPrivateKeyFromPem(pemBytes2, nil)
	Fatal(err, t)
}

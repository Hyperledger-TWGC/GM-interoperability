package interop

import (
	"testing"

	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
)

func TestLoadSM2PrivateFromPEM(t *testing.T) {
	privKeyPem := ReadFile("testdata/privateKey.pku.pem", t)
	_, err := x509.ReadPrivateKeyFromPem(privKeyPem, nil)
	Fatal(err, t)
}

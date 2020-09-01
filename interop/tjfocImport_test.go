package interop

import (
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"testing"
)

func TestLoadFromPKUGM(t *testing.T) {
	privKeyPem := ReadFile("testdata/privateKey.pku.pem", t)
	_, err := x509.ReadPrivateKeyFromPem([]byte(privKeyPem), nil)
	Fatal(err, t)
}

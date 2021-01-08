package interop

import (
	"testing"

	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
)

func TestLoadSM2PrivateFromPEM(t *testing.T) {
	pemBytes2 := ReadFile("testdata/privateKey.ccs.pem", t)
	_, err := x509.ReadPrivateKeyFromPem(pemBytes2, nil)
	Fatal(err, t)
}

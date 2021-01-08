package interop

import (
	"testing"

	"github.com/Hyperledger-TWGC/pku-gm/gmssl"
)

func TestPKUSM2KeyPemImport(t *testing.T) {
	var pem2 = "testdata/privateKey.ccs.pem"
	pemBytes2 := ReadFile(pem2, t)
	_, err := gmssl.NewPrivateKeyFromPEM(string(pemBytes2), "")
	Fatal(err, t)

}

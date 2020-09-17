package interop

import "testing"
import "github.com/Hyperledger-TWGC/pku-gm/gmssl"

func TestPKUSM2KeyPemImport(t *testing.T) {
	var privKeyPem = "testdata/privateKey.tjfoc.pem"
	pemBytes := ReadFile(privKeyPem, t)
	_, err := gmssl.NewPrivateKeyFromPEM(string(pemBytes), "")
	Fatal(err, t)
	var pem2 = "testdata/privateKey.ccs.pem"
	pemBytes2 := ReadFile(pem2, t)
	_, err = gmssl.NewPrivateKeyFromPEM(string(pemBytes2), "")
	Fatal(err, t)

}

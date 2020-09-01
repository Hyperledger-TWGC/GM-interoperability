package interop

import "github.com/Hyperledger-TWGC/pku-gm/gmssl"
import "testing"

func TestPKUSM2KeyPemExport(t *testing.T) {

	/* SM2 key pair operations */
	sm2keygenargs := [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}
	sm2sk, err := gmssl.GeneratePrivateKey("EC", sm2keygenargs, nil)

	pem, err := sm2sk.GetPEM("", "") // no encrypt mode is supported by not encouraged to use with security concern
	Fatal(err, t)
	var pemFile = "testdata/privateKey.pku.pem"
	WriteFile([]byte(pem), pemFile, t)

}

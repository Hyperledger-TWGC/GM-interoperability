package interop

import (
	"crypto/x509/pkix"

	"testing"

	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
)

func TestTJSM2Pem(t *testing.T) {
	sm2PrivKey, err := sm2.GenerateKey(nil)
	Fatal(err, t)
	pemBytes, err := x509.WritePrivateKeyToPem(sm2PrivKey, nil)
	Fatal(err, t)
	var pemFile = "testdata/tjfoc/priv.pem"
	WriteFile(pemBytes, pemFile, t)

	pubKey, _ := sm2PrivKey.Public().(*sm2.PublicKey)
	pemFile = "testdata/tjfoc/pub.pem"
	pemBytes,err = x509.WritePublicKeyToPem(pubKey)
	WriteFile(pemBytes, pemFile, t)
	Fatal(err, t)

	pemFile = "testdata/tjfoc/req.pem"
	templateReq := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test"},
		},
		SignatureAlgorithm: x509.SM2WithSM3,
	}
	pemBytes,err = x509.CreateCertificateRequestToPem(templateReq, sm2PrivKey)
	WriteFile(pemBytes, pemFile, t)
	Fatal(err, t)
}

package interop

import (
	"crypto/rand"
	"testing"

	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
)

func TestLoadFromJavaGM(t *testing.T) {
	privKeyPem := ReadFile("testdata/priv.pem", t)
	privKey, err := x509.ReadPrivateKeyFromPem(privKeyPem, nil)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyPem := ReadFile("testdata/pub.pem", t)
	pubkey, err := x509.ReadPublicKeyFromPem(pubKeyPem)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("abc")
	sign, err := privKey.Sign(rand.Reader, msg, nil) // 签名
	if err != nil {
		t.Fatal(err)
	}
	isok := pubkey.Verify(msg, sign)
	if isok != true {
		t.Errorf("Failed with verify")
	}
	certPem := ReadFile("testdata/req.pem", t)
	_, err = x509.ReadCertificateRequestFromPem(certPem)
	if err != nil {
		t.Fatal(err)
	}
}

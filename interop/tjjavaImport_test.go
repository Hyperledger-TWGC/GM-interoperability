package interop

import (
	"crypto/rand"
	"io/ioutil"
	"testing"

	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
)

func TestLoadFromJavaGM(t *testing.T) {
	privPem, err := ioutil.ReadFile("testdata/priv.pem")
	if err != nil {
		t.Fatal(err)
	}
	privKey, err := x509.ReadPrivateKeyFromPem(privPem, nil)
	if err != nil {
		t.Fatal(err)
	}
	pubkey, err := x509.ReadPublicKeyFromPem("testdata/pub.pem")
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
	_, err = x509.ReadCertificateRequestFromPem("testdata/req.pem")
	if err != nil {
		t.Fatal(err)
	}
}

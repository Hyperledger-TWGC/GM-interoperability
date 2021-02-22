package interop

import (
	"crypto/rand"
	"testing"
	"time"

	ccsutils "github.com/Hyperledger-TWGC/ccs-gm/utils"
	pku "github.com/Hyperledger-TWGC/pku-gm/gmssl"
	tj "github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	tjx509 "github.com/Hyperledger-TWGC/tjfoc-gm/x509"
)

func TestSM2(t *testing.T) {
	// generate a random string as data
	base_format := "2006-01-02 15:04:05"
	time := time.Now()
	str_time := time.Format(base_format)
	msg := []byte(str_time)
	// generate key from tj
	sm2PrivKey, err := tj.GenerateKey(rand.Reader)
	Fatal(err, t)
	pemBytes, err := tjx509.WritePrivateKeyToPem(sm2PrivKey, nil)
	Fatal(err, t)
	sm2pub := &sm2PrivKey.PublicKey
	// ccs load priv key pem
	ccsPrivKey, err := ccsutils.PEMtoPrivateKey(pemBytes, nil)
	Fatal(err, t)
	pkuPrivKey, err := pku.NewPrivateKeyFromPEM(string(pemBytes), "")
	Fatal(err, t)
	sm2pkpem, err := pkuPrivKey.GetPublicKeyPEM()
	sm2pk, err := pku.NewPublicKeyFromPEM(sm2pkpem)
	sm3ctx, err := pku.NewDigestContext(pku.SM3)
	sm2zid, err := sm2pk.ComputeSM2IDDigest("1234567812345678")

	// encrypt by tj
	d0, err := sm2pub.EncryptAsn1(msg, rand.Reader)
	Fatal(err, t)
	// decrypt by ccs
	//plain, err := ccs.Decrypt(d0, ccsPrivKey)
	// decrypt by pku

	// assert decrypt same with original

	// sign by ccs
	ccssign, err := ccsPrivKey.Sign(rand.Reader, msg, nil) // 签名
	Fatal(err, t)
	// verify by tj
	ok := sm2pub.Verify(msg, ccssign) // 公钥验证
	if !ok {
		t.Fatal("tj verify ccs sign error")
	}

	//
	err = sm3ctx.Reset()
	err = sm3ctx.Update(sm2zid)
	err = sm3ctx.Update(msg)
	digest, err := sm3ctx.Final()
	// sign by pku
	pkusign, err := pkuPrivKey.Sign("sm2sign", digest, nil)
	Fatal(err, t)
	// verify by tj
	ok = sm2pub.Verify(msg, pkusign) // 公钥验证
	if !ok {
		t.Fatal("tj verify pku sign error")
	}
	// decrypt by pku
	sm2plaintext, err := pkuPrivKey.Decrypt("sm2encrypt-with-sm3", d0, nil)
	if msg != sm2plaintext {
		t.Fatal("pku decrypt tj encrypt error")
	}
}

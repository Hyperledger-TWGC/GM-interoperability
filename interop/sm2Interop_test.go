package interop

import (
	"testing"
	"time"
	"crypto/rand"
	"fmt"

	ccsutils "github.com/Hyperledger-TWGC/ccs-gm/utils"
	pku "github.com/Hyperledger-TWGC/pku-gm/gmssl"
	tj "github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	tjx509 "github.com/Hyperledger-TWGC/tjfoc-gm/x509"

)

const base_format = "2006-01-02 15:04:05"

func TestSM2(t *testing.T) {
	// generate a random string as data
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
	// encrypt by tj
	//d0, err := sm2pub.EncryptAsn1(msg, rand.Reader)
	//Fatal(err, t)
	// decrypt by ccs
	//plain, err := ccs.Decrypt(d0, ccsPrivKey)
	// decrypt by pku

	// assert decrypt same with original

	// sign by tj
	ccssign, err := ccsPrivKey.Sign(rand.Reader, msg, nil) // 签名
	Fatal(err, t)
	fmt.Println(string(ccssign))
	// verify by ccs
	ok := sm2pub.Verify(msg, ccssign) // 公钥验证
	if !ok {
		t.Fatal("tj verify ccs sign error")
	}
	// verify by pku
	pkusign, err := pkuPrivKey.Sign("sm2sign", msg, nil) // 签名
	Fatal(err, t)
	// verify by ccs
	fmt.Println(string(pkusign))
	ok = sm2pub.Verify(msg, pkusign) // 公钥验证
	if !ok {
		t.Fatal("tj verify pku sign error")
	}
}

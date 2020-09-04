package tjfoc_gm

import (
	"crypto/rand"
	"fmt"
	"log"
	"strings"
	"testing"
)

func TestSM2(t *testing.T) {
	priv, err := GenerateKey(rand.Reader) // 生成密钥对
	if err != nil {
		t.Fatal(err)
	}
	//fmt.Printf("%v\n", priv.Curve.IsOnCurve(priv.X, priv.Y)) // 验证是否为sm2的曲线
	pub := &priv.PublicKey
	msg := []byte("123456")
	d0, err := pub.Encrypt(msg,rand.Reader)
	if err != nil {
		fmt.Printf("Error: failed to encrypt %s: %v\n", msg, err)
		return
	}
	// fmt.Printf("Cipher text = %v\n", d0)
	d1, err := priv.Decrypt(d0)
	if err != nil {
		fmt.Printf("Error: failed to decrypt: %v\n", err)
	}
	//fmt.Printf("clear text = %s\n", d1)
	if strings.Compare(string(msg),string(d1))==0 {
		log.Println("Is the same!")
	}else{
		log.Println("Isn't the same!")
	}

	signedData, err := priv.Sign(rand.Reader,msg, nil)   // 私钥签名
	if err != nil {
		t.Fatal(err)
	}
	ok := priv.PublicKey.Verify(msg, signedData) // 公钥验证
	if ok != true {
		log.Printf("Verify error\n")
	} else {
		log.Printf("Verify ok\n")
	}


}
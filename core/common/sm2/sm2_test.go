package sm2

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func TestSM2(t *testing.T){
	priv, err := GenerateKey(rand.Reader) // 生成密钥对
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("is on cure ? %v\n", priv.Curve.IsOnCurve(priv.X, priv.Y)) // 验证是否为sm2的曲线
	pub := &priv.PublicKey
	msg := []byte("123456")
	fmt.Printf("Plain text= %v\n",string(msg))
	d0, err := pub.Encrypt(msg)
	if err != nil {
		fmt.Printf("Error: failed to encrypt %s: %v\n", msg, err)
		return
	}
	//fmt.Printf("Cipher text = %v\n", d0)
	d1, err := priv.Decrypt(d0)
	if err != nil {
		fmt.Printf("Error: failed to decrypt: %v\n", err)
	}
	fmt.Printf("clear text = %v\n", string(d1))

	signedData, err := priv.Sign(msg, nil)   // 私钥签名
	if err != nil {
		t.Fatal(err)
	}
	ok := priv.PublicKey.Verify(msg, signedData) // 公钥验证
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}



}

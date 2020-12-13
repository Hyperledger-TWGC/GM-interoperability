package interop

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm4"
	"log"
	"testing"
)

/**
1. 执行Hyperledger-TWGC/java-gm中的SM4UtilTest.sm4Interaction4Encrypt()方法，获得Java sm4加密密文，更新代码中待解密参数；
2. 执行本测试方法，核对解密结果，并获得golang sm4加密密文，更新Hyperledger-TWGC/java-gm中的SM4UtilTest.sm4Interaction4Decrypt()
	中待解密参数；
*/
func TestSM4InteractionWithJava(t *testing.T) {
	// 128比特密钥
	key := []byte("1234567890abcdef")
	fmt.Println("key = " + string(key))
	// 128比特iv
	//iv := make([]byte, sm4.BlockSize)
	iv := []byte("ilovegolangjava.")
	fmt.Println("iv = " + string(iv))

	// 加密明文以供Java sm4解密验证
	data := []byte("I am encrypted by golang SM4.")
	ciphertxt, err := sm4Encrypt(key, iv, data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("加密结果: %x\n", ciphertxt)

	// 解密Java sm4加密的密文
	ciphertxt, err1 := hex.DecodeString("8781d981f7ffd6c1a780f8b213f596aa6c7e99b94e8b6e0b9147a97a47b08bc5")
	if err1 != nil {
		log.Fatal(err1)
	}
	plaintxt, err1 := sm4Decrypt(key, iv, ciphertxt)
	fmt.Printf("解密结果: %s\n", plaintxt)
}

func sm4Encrypt(key, iv, plainText []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData := pkcs7Padding(plainText, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cryted := make([]byte, len(origData))
	blockMode.CryptBlocks(cryted, origData)
	return cryted, nil
}

func sm4Decrypt(key, iv, cipherText []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(cipherText))
	blockMode.CryptBlocks(origData, cipherText)
	origData = pkcs7UnPadding(origData)
	return origData, nil
}

// pkcs7填充
func pkcs7Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// pkcs5填充
func pkcs5Padding(src []byte, blockSize int) []byte {
	return pkcs7Padding(src, 8)
}

func pkcs7UnPadding(src []byte) []byte {
	length := len(src)
	if length == 0 {
		return src
	}
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

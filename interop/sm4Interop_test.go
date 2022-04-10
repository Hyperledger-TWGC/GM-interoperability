package interop

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	ccs "github.com/Hyperledger-TWGC/ccs-gm/sm4"
	pku "github.com/Hyperledger-TWGC/pku-gm/gmssl"
	tj "github.com/Hyperledger-TWGC/tjfoc-gm/sm4"
)

func TestSM4(t *testing.T) {
	base_format := "2006-01-02 15:04:05"
	//random data
	time := time.Now()
	str_time := time.Format(base_format)
	msg := []byte(str_time)

	// hard code data for debug usage if needed
	// []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	// []byte("0123456789abcdef012345678")

	sourceDef := os.Getenv("SOURCE")
	targetDef := os.Getenv("TARGET")

	fmt.Println("source lib " + sourceDef)
	fmt.Println("target lib " + targetDef)
	fmt.Printf("msg = %x\n", msg)
	// generate key
	// hard code key for debug usage if needed
	key := []byte("1234567890abcdef")

	//keyLen, _ := pku.GetCipherKeyLength(pku.SMS4)
	//key, _ := pku.GenerateRandom(keyLen)
	fmt.Printf("key = %v\n", key)
	// ECB

	var ecbMsg []byte
	var ecbDec []byte
	var err error
	// lib a encrypt
	if sourceDef == "TJ" {
		ecbMsg, err = tj.Sm4Ecb(key, msg, true)
		if err != nil {
			t.Errorf("sm4 enc error:%s", err)
			return
		}
	}
	if sourceDef == "CCS" {
		ecbMsg, err = ccs.Sm4Ecb(key, msg, ccs.ENC)
		if err != nil {
			t.Errorf("sm4 enc error:%s", err)
			return
		}
	}
	if sourceDef == "PKU" {
		//ecbMsg
		inData := pkcs7Padding(msg)
		ecbMsg = make([]byte, len(inData))
		//loop for each 16 bytes of msg
		for i := 0; i < len(inData)/16; i++ {
			TempMsg, err := pku.CipherECBenc(inData[i*16:(i+1)*16], key)
			if err != nil {
				t.Errorf("sm4 enc error:%s", err)
				return
			}
			//append into ecbMsg
			copy(ecbMsg[i*16:i*16+16], TempMsg)
		}

	}
	fmt.Printf("ecbMsg = %x\n", ecbMsg)
	fmt.Println(ecbMsg)
	// lib b decrypt
	if targetDef == "TJ" {
		ecbDec, err = tj.Sm4Ecb(key, ecbMsg, false)
		if err != nil {
			t.Errorf("sm4 dec error:%s", err)
			return
		}
	}
	if targetDef == "CCS" {
		ecbDec, err = ccs.Sm4Ecb(key, ecbMsg, ccs.DEC)
		if err != nil {
			t.Errorf("sm4 dec error:%s", err)
			return
		}
	}
	if targetDef == "PKU" {
		ecbDec = make([]byte, len(ecbMsg))
		for i := 0; i < len(ecbMsg)/16; i++ {
			in_tmp := ecbMsg[i*16 : i*16+16]
			out_tmp := make([]byte, 16)
			out_tmp, err = pku.CipherECBdec(in_tmp, key)
			if err != nil {
				t.Errorf("sm4 dec error:%s", err)
				return
			}
			copy(ecbDec[i*16:(i+1)*16], out_tmp)
		}
		ecbDec, _ = pkcs7UnPadding(ecbDec)
	}
	fmt.Printf("ecbDec = %x\n", ecbDec)
	fmt.Println(ecbDec)
	// compare
	if string(msg) != string(ecbDec) {
		t.Errorf("sm4 enc and dec failed")
	}
}

func pkcs7Padding(src []byte) []byte {
	padding := 16 - len(src)%16
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])
	if unpadding > 16 || unpadding == 0 {
		return nil, errors.New("Invalid pkcs7 padding (unpadding > BlockSize || unpadding == 0)")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("Invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}

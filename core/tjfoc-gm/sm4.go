package tjfoc_gm

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"

	//core_SM4_I "github.com/Hyperledger-TWGC/fabric-gm-plugins/core"
	tjfoc_gm_sm4 "github.com/Hyperledger-TWGC/tjfoc-gm/sm4"
	"log"
)


type SM4_I interface {
	BlockSize() int
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)

	//Transform
	//invoke other function
	//Transform(str string,parms ...interface{}) []interface{}
}

var sm4 tjfoc_gm_sm4.Sm4Cipher

type SM4 struct {

}


func (c *SM4) BlockSize() int {
	return sm4.BlockSize()
}
func NewSM4() SM4_I {

	var sm4_ SM4
	return &sm4_
}

func (c *SM4) Encrypt(dst, src []byte) {
	sm4.Encrypt(dst,src)
}

func (c *SM4) Decrypt(dst, src []byte) {
  sm4.Decrypt(dst,src)
}

//func (c *SM4) Transform(str string,parms ...interface{}) []interface{}{
//
//	var inter []interface{}
//	if str == "NewCipher"{
//       //parms[0] []byte
//		key:=parms[0].([]byte)
//		inter =make([]interface{},2)
//		ci,err:= NewCipher(key)
//		fmt.Println(reflect.TypeOf(ci))
//       inter[0]=ci
//       inter[1]=err
//       return inter
//	}else if str == "others"{
//		//TODO
//		// Your can write other here
//		return inter
//
//	}else { //inter == nil  str no found
//		log.Println("SM4 Transform failed!")
//		return inter
//
//		}
//}

func NewCipher(key []byte) (cipher.Block, error) {
	log.Println("tjfoc")
	ci,err:=tjfoc_gm_sm4.NewCipher(key)
	if err !=nil {
		return nil, err
	}
	return ci,err
}

func ReadKeyFromMem(data []byte, pwd []byte) ([]byte, error) {
	sm4key,err:=readKeyFromMem(data,pwd)
	if err !=nil {
		return nil, err
	}
	return sm4key,err
}

func WriteKeytoMem(key []byte, pwd []byte) ([]byte, error) {
	data,err:=writeKeytoMem(key,pwd)
	if err !=nil {
		return nil, err
	}
	return data,err
}

func ReadKeyFromPem(FileName string, pwd []byte) ([]byte, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	return readKeyFromMem(data, pwd)
}

func WriteKeyToPem(FileName string, key []byte, pwd []byte) error {
	pemBytes, err := writeKeytoMem(key, pwd)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(FileName, pemBytes, 0666)
	if err != nil {
		return err
	}
	return nil
}

func readKeyFromMem(data []byte, pwd []byte) ([]byte, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("SM4: pem decode failed")
	}
	if x509.IsEncryptedPEMBlock(block) {
		if block.Type != "SM4 ENCRYPTED KEY" {
			return nil, errors.New("SM4: unknown type")
		}
		if pwd == nil {
			return nil, errors.New("SM4: need passwd")
		}
		data, err := x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	if block.Type != "SM4 KEY" {
		return nil, errors.New("SM4: unknown type")
	}
	return block.Bytes, nil
}

func writeKeytoMem(key []byte, pwd []byte) ([]byte, error) {
	if pwd != nil {
		block, err := x509.EncryptPEMBlock(rand.Reader,
			"SM4 ENCRYPTED KEY", key, pwd, x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(block), nil
	} else {
		block := &pem.Block{
			Type:  "SM4 KEY",
			Bytes: key,
		}
		return pem.EncodeToMemory(block), nil
	}
}
package tjfoc_gm

import (
	"crypto/cipher"
	"fmt"
	//core_SM4_I "github.com/Hyperledger-TWGC/fabric-gm-plugins/core"
	tjfoc_gm_sm4 "github.com/Hyperledger-TWGC/tjfoc-gm/sm4"
	"log"
	"reflect"
)


type SM4_I interface {
	BlockSize() int
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)

	//Transform
	//invoke other function
	Transform(str string,parms ...interface{}) []interface{}
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

func (c *SM4) Transform(str string,parms ...interface{}) []interface{}{

	var inter []interface{}
	if str == "NewCipher"{
       //parms[0] []byte
		key:=parms[0].([]byte)
		inter =make([]interface{},2)
		ci,err:= NewCipher(key)
		fmt.Println(reflect.TypeOf(ci))
       inter[0]=ci
       inter[1]=err
       return inter
	}else if str == "others"{
		//TODO
		// Your can write other here
		return inter

	}else { //inter == nil  str no found
		log.Println("SM4 Transform failed!")
		return inter

		}
}

func NewCipher(key []byte) (cipher.Block, error) {
	log.Println("tjfoc")
	ci,err:=tjfoc_gm_sm4.NewCipher(key)
	return ci,err
}

func ReadKeyFromMem(data []byte, pwd []byte) ([]byte, error) {
	sm4key,err:=tjfoc_gm_sm4.ReadKeyFromMem(data,pwd)
	return sm4key,err
}
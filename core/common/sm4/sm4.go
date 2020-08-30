/*
Copyright Hyperledger - Technical Working Group China. 2020 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package sm4

import (
	"crypto/cipher"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core"
	tjfoc_gm "github.com/Hyperledger-TWGC/fabric-gm-plugins/core/tjfoc-gm"
	"log"
)
/**
Author: yzwyzwyzw1(Github ID)
email: 1957855254@qq.com
*/
const BlockSize = 16

type SM4_I interface {
	BlockSize() int
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)

	//Transform
	//invoke other function
	Transform(str string,parms ...interface{}) []interface{}
}

func NewSM4()  SM4_I{

	var gmopts string=core.NewGM()
	switch gmopts {
		case "tjfoc-gm":{
			log.Println("tjfoc-gm-sm4")
			return tjfoc_gm.NewSM4()
		}
			//case "ccs-gm":{
			//
			//}
			//case "pku-gm":{
			//
			//}
		default:{
			return tjfoc_gm.NewSM4()
		}
	}
}


func NewCipher(key []byte) (cipher.Block, error) {

	var gmopts string=core.NewGM()
	switch gmopts {
		case "tjfoc-gm":{
			log.Println("tjfoc-gm")
			ci,err:=tjfoc_gm.NewCipher(key)
			return ci,err
		}
			//case "ccs-gm":{
			//
			//}
			//case "pku-gm":{
			//
			//}
		default:{
			ci,err:=tjfoc_gm.NewCipher(key)
			return ci,err
		}
	}
}

func ReadKeyFromMem(data []byte, pwd []byte) ([]byte, error) {
		var gmopts string=core.NewGM()
		switch gmopts {
			case "tjfoc-gm":{
				return tjfoc_gm.ReadKeyFromMem(data,pwd)
			}
				//case "ccs-gm":{
				//
				//}
				//case "pku-gm":{
				//
				//}
			default:{
				return tjfoc_gm.ReadKeyFromMem(data,pwd)
			}
		}


}

func ReadKeyFromPem(FileName string, pwd []byte) ([]byte, error) {
	var gmopts string=core.NewGM()
	switch gmopts {
		case "tjfoc-gm":{
			return tjfoc_gm.ReadPrivateKeyFromPem(FileName,pwd)
		}
			//case "ccs-gm":{
			//
			//}
			//case "pku-gm":{
			//
			//}
		default:{
			return tjfoc_gm.ReadPrivateKeyFromPem(FileName,pwd)
		}
	}
}


func WriteKeytoMem(key []byte, pwd []byte) ([]byte, error) {
	var gmopts string=core.NewGM()
	switch gmopts {
		case "tjfoc-gm":{
			return tjfoc_gm.WritePrivateKeytoMem(key,pwd)
		}
			//case "ccs-gm":{
			//
			//}
			//case "pku-gm":{
			//
			//}
		default:{
			return tjfoc_gm.WritePrivateKeytoMem(key,pwd)
		}
	}
}


func WriteKeyToPem(FileName string, key []byte, pwd []byte) error {
	var gmopts string=core.NewGM()
	switch gmopts {
		case "tjfoc-gm":{
			return tjfoc_gm.WritePublicKeytoPem(FileName,key)
		}
			//case "ccs-gm":{
			//
			//}
			//case "pku-gm":{
			//
			//}
		default:{
			return tjfoc_gm.WritePublicKeytoPem(FileName,key)
		}
	}
}


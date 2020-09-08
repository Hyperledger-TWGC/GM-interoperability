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
package sm2

import (
	"crypto"
	"crypto/elliptic"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core"
	tjfoc_gm "github.com/Hyperledger-TWGC/fabric-gm-plugins/core/tjfoc-gm"
	"io"
	"log"
	"math/big"
)

/**
Author: yzwyzwyzw1(Github ID)
email: 1957855254@qq.com
*/
type PublicKey_I interface {
	Verify(msg []byte, sign []byte) bool
	Encrypt(data []byte) ([]byte, error)
}

type PrivateKey_I interface {
	Sign(msg []byte, uid []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
}

type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

type PrivateKey struct {
	PublicKey
	D *big.Int
}

func (pub *PublicKey) Verify(msg []byte, sign []byte) bool {
	var gmopts string=core.NewGM()
	switch gmopts {
	case "tjfoc-gm":
		{


			log.Println("tjfoc-gm-sm2")
			pub2:=tjfoc_gm.PublicKey{}
			pub2.X=pub.X
			pub2.Y=pub.Y
			pub2.Curve=pub.Curve
			return pub2.Verify(msg,sign)

		}
		//case "ccs-gm":{
		//
		//}
		//case "pku-gm":{
		//
		//}
	default:
		{

			log.Println("tjfoc-gm-sm2")
			pub2:=tjfoc_gm.PublicKey{}
			pub2.X=pub.X
			pub2.Y=pub.Y
			pub2.Curve=pub.Curve
			return pub2.Verify(msg,sign)
		}
	}


}

func (priv *PrivateKey) Sign(msg []byte, uid []byte) ([]byte, error) {

	var gmopts string=core.NewGM()
	switch gmopts {
	case "tjfoc-gm":
		{
			log.Println("tjfoc-gm-sm2")
			priv2:=tjfoc_gm.PrivateKey{}
			priv2.X=priv.X
			priv2.Y=priv.Y
			priv2.D=priv.D
			priv2.Curve=priv.Curve
			return priv2.Sign(msg,uid)

		}
		//case "ccs-gm":{
		//
		//}
		//case "pku-gm":{
		//
		//}
	default:
		{
			log.Println("tjfoc-gm-sm2")
			priv2:=tjfoc_gm.PrivateKey{}
			priv2.X=priv.X
			priv2.Y=priv.Y
			priv2.D=priv.D
			priv2.Curve=priv.Curve
			return priv2.Sign(msg,uid)
		}
	}

}

func (priv *PrivateKey) Public() crypto.PublicKey  {
	var gmopts string=core.NewGM()
	switch gmopts {
	case "tjfoc-gm":
		{
			log.Println("tjfoc-gm-sm2")
			priv2:=tjfoc_gm.PrivateKey{}
			priv2.X=priv.X
			priv2.Y=priv.Y
			priv2.D=priv.D
			priv2.Curve=priv.Curve
			return priv2.PublicKey

		}
		//case "ccs-gm":{
		//
		//}
		//case "pku-gm":{
		//
		//}
	default:
		{
			log.Println("tjfoc-gm-sm2")
			priv2:=tjfoc_gm.PrivateKey{}
			priv2.X=priv.X
			priv2.Y=priv.Y
			priv2.D=priv.D
			priv2.Curve=priv.Curve
			return priv2.PublicKey
		}
	}

}

func (pub *PublicKey) Encrypt(data []byte) ([]byte, error) {
	var gmopts string=core.NewGM()
	switch gmopts {
	case "tjfoc-gm":
		{


			log.Println("tjfoc-gm-sm2")
			pub2:=tjfoc_gm.PublicKey{}
			pub2.X=pub.X
			pub2.Y=pub.Y
			pub2.Curve=pub.Curve
			return pub2.Encrypt(data)

		}
		//case "ccs-gm":{
		//
		//}
		//case "pku-gm":{
		//
		//}
	default:
		{

			log.Println("tjfoc-gm-sm2")
			pub2:=tjfoc_gm.PublicKey{}
			pub2.X=pub.X
			pub2.Y=pub.Y
			pub2.Curve=pub.Curve
			return pub2.Encrypt(data)
		}
	}

}

func (priv *PrivateKey) Decrypt(data []byte) ([]byte, error) {
	var gmopts string=core.NewGM()
	switch gmopts {
	case "tjfoc-gm":
		{
			log.Println("tjfoc-gm-sm2")
			priv2:=tjfoc_gm.PrivateKey{}
			priv2.X=priv.X
			priv2.Y=priv.Y
			priv2.D=priv.D
			priv2.Curve=priv.Curve
			return priv2.Decrypt(data)

		}
		//case "ccs-gm":{
		//
		//}
		//case "pku-gm":{
		//
		//}
	default:
		{
			log.Println("tjfoc-gm-sm2")
			priv2:=tjfoc_gm.PrivateKey{}
			priv2.X=priv.X
			priv2.Y=priv.Y
			priv2.D=priv.D
			priv2.Curve=priv.Curve
			return priv2.Decrypt(data)
		}
	}


}

func P256() elliptic.Curve{
	var gmopts string=core.NewGM()
	switch gmopts {
	case "tjfoc-gm":
		{

			return tjfoc_gm.P256()

		}
		//case "ccs-gm":{
		//
		//}
		//case "pku-gm":{
		//
		//}
	default:
		{
			return tjfoc_gm.P256()
		}
	}

}
func sm2PrivateKey() PrivateKey_I {
	var gmopts string=core.NewGM()
	switch gmopts {
	case "tjfoc-gm":
		{
			log.Println("tjfoc-gm-sm2")
			return tjfoc_gm.NewSM2PrivateKey()

		}
		//case "ccs-gm":{
		//
		//}
		//case "pku-gm":{
		//
		//}
	default:
		{
			return tjfoc_gm.NewSM2PrivateKey()
		}
	}

}

func sm2PublicKey() PublicKey_I {
	var gmopts string=core.NewGM()
	switch gmopts {
		case "tjfoc-gm":
			{	log.Println("tjfoc-gm-sm2")
				return tjfoc_gm.NewSM2PublicKey()
			}
			//case "ccs-gm":{
			//
			//}
			//case "pku-gm":{
			//
			//}
		default:
			{
				return tjfoc_gm.NewSM2PublicKey()
			}
	}
}

func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	var gmopts string=core.NewGM()
	switch gmopts {
	case "tjfoc-gm":
		{	log.Println("tjfoc-gm-sm2")
			priv,err:=tjfoc_gm.GenerateKey(rand)
			if err != nil{
				log.Println("Generate key failed")
			}
			var _priv PrivateKey
			_priv.X=priv.X
			_priv.Y=priv.Y
			_priv.D=priv.D
			_priv.Curve=priv.Curve
			return &_priv,err
		}
		//case "ccs-gm":{
		//
		//}
		//case "pku-gm":{
		//
		//}
	default:
		{
			priv,err:=tjfoc_gm.GenerateKey(rand)
			if err != nil{
				log.Println("Generate key failed")
			}
			var _priv PrivateKey
			_priv.X=priv.X
			_priv.X=priv.Y
			_priv.D=priv.D
			_priv.Curve=priv.Curve
			return &_priv,err
		}
	}

}


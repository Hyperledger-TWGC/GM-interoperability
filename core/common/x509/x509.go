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
package x509

import (
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm2"
	tjfoc_gm "github.com/Hyperledger-TWGC/fabric-gm-plugins/core/tjfoc-gm"
)
/**
Author: yzwyzwyzw1(Github ID)
email: 1957855254@qq.com
*/

func MarshalPKISM2PublicKey(key *sm2.PublicKey)([]byte,error){
	var gmopts string=core.NewGM()
	switch gmopts {
		case "tjfoc-gm":{
			return tjfoc_gm.MarshalPKISM2PublicKey(key)
		}
			//case "ccs-gm":{
			//
			//}
			//case "pku-gm":{
			//
			//}
		default:{
			return tjfoc_gm.MarshalPKISM2PublicKey(key)
		}
	}

}

func MarshalPKISM2PrivateKey(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	var gmopts string=core.NewGM()
	switch gmopts {
		case "tjfoc-gm":{
			return tjfoc_gm.MarshalPKISM2PrivateKey(key,pwd)
		}
			//case "ccs-gm":{
			//
			//}
			//case "pku-gm":{
			//
			//}
		default:{
			return tjfoc_gm.MarshalPKISM2PrivateKey(key,pwd)
		}
	}
}

func MarshalECSM2PrivateKey(key *sm2.PrivateKey) ([]byte, error) {
	var gmopts string=core.NewGM()
	switch gmopts {
	case "tjfoc-gm":{

		sm2_priv:=sm2.PrivateKey{}
		sm2_priv.X=key.X
		sm2_priv.Y=key.Y
		sm2_priv.D=key.D
		sm2_priv.Curve=key.Curve
		key,err:=tjfoc_gm.MarshalECSM2PrivateKey(&sm2_priv)

		return key,nil
	}
		//case "ccs-gm":{
		//
		//}
		//case "pku-gm":{
		//
		//}
	default:{
		sm2_priv:=sm2.PrivateKey{}
		sm2_priv.X=key.X
		sm2_priv.Y=key.Y
		sm2_priv.D=key.D
		sm2_priv.Curve=key.Curve
		key,err:=tjfoc_gm.MarshalECSM2PrivateKey(&sm2_priv)

		return key,nil
	}
	}

}
func ParsePKISM2PrivateKey(der []byte) (*sm2.PrivateKey, error) {
	var gmopts string=core.NewGM()
	switch gmopts {
		case "tjfoc-gm":{
			sm2_priv,err:=tjfoc_gm.ParsePKISM2PrivateKey(der)
			if err !=nil {
				return nil, err
			}
			priv:=sm2.PrivateKey{}
			priv.D=sm2_priv.D
			priv.X=sm2_priv.X
			priv.Y=sm2_priv.Y
			priv.Curve=sm2_priv.Curve
			return &priv,nil
		}
			//case "ccs-gm":{
			//
			//}
			//case "pku-gm":{
			//
			//}
		default:{
			sm2_priv,err:=tjfoc_gm.ParsePKISM2PrivateKey(der)
			if err !=nil {
				return nil, err
			}
			priv:=sm2.PrivateKey{}
			priv.D=sm2_priv.D
			priv.X=sm2_priv.X
			priv.Y=sm2_priv.Y
			priv.Curve=sm2_priv.Curve
			return &priv,nil
		}
	}

}


func ParsePKISM2PublicKey(der []byte) (*sm2.PublicKey, error) {
	var gmopts string=core.NewGM()
	switch gmopts {
		case "tjfoc-gm":{
			sm2_pub,err:=tjfoc_gm.ParsePKISM2PublicKey(der)
			if err !=nil {
				return nil, err
			}
			pub:=sm2.PublicKey{}
			pub.X=sm2_pub.X
			pub.Y=sm2_pub.Y
			pub.Curve=sm2_pub.Curve
			return &pub,nil
		}
			//case "ccs-gm":{
			//
			//}
			//case "pku-gm":{
			//
			//}
		default:{
			sm2_pub,err:=tjfoc_gm.ParsePKISM2PublicKey(der)
			if err !=nil {
				return nil, err
			}
			pub:=sm2.PublicKey{}
			pub.X=sm2_pub.X
			pub.Y=sm2_pub.Y
			pub.Curve=sm2_pub.Curve
			return &pub,nil
		}
	}
}

func WritePrivateKeytoMem(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	var gmopts string=core.NewGM()
	switch gmopts {
		case "tjfoc-gm":{
			priv:=sm2.PrivateKey{}
			priv.D=key.D
			priv.X=key.X
			priv.Y=key.Y
			priv.Curve=key.Curve
			return tjfoc_gm.WritePrivateKeytoMem(priv,pwd)
		}
			//case "ccs-gm":{
			//
			//}
			//case "pku-gm":{
			//
			//}
		default:{
			priv:=sm2.PrivateKey{}
			priv.D=key.D
			priv.X=key.X
			priv.Y=key.Y
			priv.Curve=key.Curve
			return tjfoc_gm.WritePrivateKeytoMem(priv,pwd)
		}
	}

}


func WritePrivateKeytoPem(FileName string, key *sm2.PrivateKey, pwd []byte) (err error) {
	var gmopts string=core.NewGM()
	switch gmopts {
		case "tjfoc-gm":{
			priv:=sm2.PrivateKey{}
			priv.D=key.D
			priv.X=key.X
			priv.Y=key.Y
			priv.Curve=key.Curve
			return tjfoc_gm.WritePrivateKeytoPem(FileName,key,pwd)
		}
			//case "ccs-gm":{
			//
			//}
			//case "pku-gm":{
			//
			//}
		default:{
			priv:=sm2.PrivateKey{}
			priv.D=key.D
			priv.X=key.X
			priv.Y=key.Y
			priv.Curve=key.Curve
			return tjfoc_gm.WritePrivateKeytoPem(FileName,key,pwd)
		}
	}
}


func WritePublicKeytoMem(key *sm2.PublicKey) ([]byte, error) {
	var gmopts string=core.NewGM()
	switch gmopts {
		case "tjfoc-gm":{
			return WritePublicKeytoMem(key)
		}
			//case "ccs-gm":{
			//
			//}
			//case "pku-gm":{
			//
			//}
		default:{
			return WritePublicKeytoMem(key)
		}
	}
}


func WritePublicKeytoPem(FileName string, key *sm2.PublicKey) (err error) {
	var gmopts string=core.NewGM()
	switch gmopts {
		case "tjfoc-gm":{
			return WritePublicKeytoPem(FileName,key)
		}
			//case "ccs-gm":{
			//
			//}
			//case "pku-gm":{
			//
			//}
		default:{
			return WritePublicKeytoPem(FileName,key)
		}
	}
}


func ReadPrivateKeyFromMem(data []byte, pwd []byte) (*sm2.PrivateKey, error) {
	var gmopts string=core.NewGM()
	switch gmopts {
		case "tjfoc-gm":{

		    key,err:=tjfoc_gm.ReadPrivateKeyFromMem(data,pwd)
		    if err != nil{
		    	return nil, err
			}
			priv:=sm2.PrivateKey{}
			priv.D=key.D
			priv.X=key.X
			priv.Y=key.Y
			priv.Curve=key.Curve
			return &priv,nil
		}
			//case "ccs-gm":{
			//
			//}
			//case "pku-gm":{
			//
			//}
		default:{
			key,err:=tjfoc_gm.ReadPrivateKeyFromMem(data,pwd)
			if err != nil{
				return nil, err
			}
			priv:=sm2.PrivateKey{}
			priv.D=key.D
			priv.X=key.X
			priv.Y=key.Y
			priv.Curve=key.Curve
			return &priv,nil
		}
	}
}


func ReadPrivateKeyFromPem(FileName string, pwd []byte) (*sm2.PrivateKey, error) {
	var gmopts string=core.NewGM()
	switch gmopts {
		case "tjfoc-gm":{
			key,err:=tjfoc_gm.ReadPrivateKeyFromPem(FileName,pwd)
			if err != nil{
				return nil, err
			}
			priv:=sm2.PrivateKey{}
			priv.D=key.D
			priv.X=key.X
			priv.Y=key.Y
			priv.Curve=key.Curve
			return &priv,nil
		}
			//case "ccs-gm":{
			//
			//}
			//case "pku-gm":{
			//
			//}
		default:{
			key,err:=tjfoc_gm.ReadPrivateKeyFromPem(FileName,pwd)
			if err != nil{
				return nil, err
			}
			priv:=sm2.PrivateKey{}
			priv.D=key.D
			priv.X=key.X
			priv.Y=key.Y
			priv.Curve=key.Curve
			return &priv,nil
		}
	}
}


func ReadPublicKeyFromMem(data []byte) (*sm2.PublicKey, error) {
	var gmopts string=core.NewGM()
	switch gmopts {
		case "tjfoc-gm":{
			sm2_pub,err:=tjfoc_gm.ReadPublicKeyFromMem(data)
			if err !=nil {
				return nil, err
			}
			pub:=sm2.PublicKey{}
			pub.X=sm2_pub.X
			pub.Y=sm2_pub.Y
			pub.Curve=sm2_pub.Curve
			return &pub,nil
		}
			//case "ccs-gm":{
			//
			//}
			//case "pku-gm":{
			//
			//}
		default:{
			sm2_pub,err:=tjfoc_gm.ReadPublicKeyFromMem(data)
			if err !=nil {
				return nil, err
			}
			pub:=sm2.PublicKey{}
			pub.X=sm2_pub.X
			pub.Y=sm2_pub.Y
			pub.Curve=sm2_pub.Curve
			return &pub,nil
		}
	}
}


func ReadPublicKeyFromPem(FileName string) (*sm2.PublicKey, error) {
	var gmopts string=core.NewGM()
	switch gmopts {
		case "tjfoc-gm":{
			sm2_pub,err:=tjfoc_gm.ReadPublicKeyFromPem(FileName)
			if err !=nil {
				return nil, err
			}
			pub:=sm2.PublicKey{}
			pub.X=sm2_pub.X
			pub.Y=sm2_pub.Y
			pub.Curve=sm2_pub.Curve
			return &pub,nil
		}
			//case "ccs-gm":{
			//
			//}
			//case "pku-gm":{
			//
			//}
		default:{
			sm2_pub,err:=tjfoc_gm.ReadPublicKeyFromPem(FileName)
			if err !=nil {
				return nil, err
			}
			pub:=sm2.PublicKey{}
			pub.X=sm2_pub.X
			pub.Y=sm2_pub.Y
			pub.Curve=sm2_pub.Curve
			return &pub,nil
		}
	}
}












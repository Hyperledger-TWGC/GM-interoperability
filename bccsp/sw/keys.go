/*
Copyright IBM Corp. 2016 All Rights Reserved.

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

package sw

import (

	"crypto/elliptic"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm2"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm4"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/x509"
)

// struct to hold info required for PKCS#8
type pkcs8Info struct {
	Version             int
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

var oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	}
	return nil, false
}


//--------------------------------------------------------//
// PublicKeyToDER marshals a public key to the der format
func publicKeyToDER(publicKey *sm2.PublicKey) ([]byte, error) {

	PubASN1, err := x509.MarshalPKISM2PublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return PubASN1, nil
}

// DERToPublicKey unmarshals a der to public key
func derToPublicKey(raw []byte) (pub *sm2.PublicKey, err error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid DER. It must be different from nil.")
	}

	key, err := x509.ParsePKISM2PublicKey(raw)

	return key, err
}

// DERToPrivateKey unmarshals a der to private key
func derToPrivateKey(der []byte) (key *sm2.PrivateKey, err error) {



	if key, err =  sm2.ParsePKCS8PrivateKey(der,nil);err == nil {
		//fmt.Println("123eqq")
		return
	}
	if key, err = sm2.ParsePKCS8EcryptedSM2PrivateKey(der,nil); err == nil {
		//fmt.Println("123")
		return
	}

	return nil, errors.New("Invalid key type. The DER must contain an rsa.PrivateKey or ecdsa.PrivateKey")
}



func privateKeyToDER(privateKey *sm2.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("invalid sm2 private key. It must be different from nil")
	}

	return x509.MarshalECSM2PrivateKey(privateKey)
}

func privateKeyToPEM(privateKey *sm2.PrivateKey, pwd []byte) ([]byte, error) {

	fmt.Println("privateKey",privateKey)
	if privateKey == nil {
		return nil, errors.New("Invalid key. It must be different from nil.")
	}

	return x509.WritePrivateKeytoMem(privateKey, pwd)

}

func pemToPrivateKey(raw []byte, pwd []byte) (*sm2.PrivateKey, error) {

	priv,err :=x509.ReadPrivateKeyFromMem(raw,pwd)
	if err !=nil {
		return nil, errors.New("error pem,can not read private key from pem")
	}
	return priv,nil
}

func publicKeyToPEM(publicKey *sm2.PublicKey, pwd []byte) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("Invalid key. It must be different from nil.")
	}
	return x509.WritePublicKeytoMem(publicKey,pwd)
}

func pemToPublicKey(raw []byte, pwd []byte) (*sm2.PublicKey, error) {

	pub,err := x509.ReadPublicKeyFromMem(raw,pwd)
	if err !=nil {
		return nil, errors.New("error pem,can not read private key from pem")
	}
	return pub,nil

}



// ------------------------------------------- //
func sm4ToPEM(raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "SM4 PRIVATE KEY", Bytes: raw})
}

// PEMtoAES extracts from the PEM an SM4 key
func pemToSM4(raw []byte, pwd []byte) ([]byte, error) {

	sm4key,err := sm4.ReadKeyFromMem(raw,pwd)
	if err != nil {
		return nil, errors.New("Invalid key. It must be different from nil.")
	}
	return sm4key,nil
}


// SM4toEncryptedPEM encapsulates an SM4 key in the encrypted PEM format
func sm4ToEncryptedPEM(raw []byte, pwd []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid aes key. It must be different from nil")
	}

	return sm4.WriteKeytoMem(raw,pwd)

}
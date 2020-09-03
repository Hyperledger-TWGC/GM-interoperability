/*
Copyright Hyperledger - Technical Working Group China. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sw

import (
	"crypto/rand"
	"errors"
	mocks2 "github.com/Hyperledger-TWGC/fabric-gm-plugins/bccsp/mocks"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/bccsp/sw/mocks"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm2"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/x509"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/stretchr/testify/require"
	"reflect"
	"testing"
)

func TestKeyImport(t *testing.T) {
	t.Parallel()

	expectedRaw := []byte{1, 2, 3}
	expectedOpts := &mocks2.KeyDerivOpts{EphemeralValue: true}
	expectetValue := &mocks2.MockKey{BytesValue: []byte{1, 2, 3, 4, 5}}
	expectedErr := errors.New("Expected Error")

	keyImporters := make(map[reflect.Type]sw.KeyImporter)
	keyImporters[reflect.TypeOf(&mocks2.KeyDerivOpts{})] = &mocks.KeyImporter{
		RawArg:  expectedRaw,
		OptsArg: expectedOpts,
		Value:   expectetValue,
		Err:     expectedErr,
	}
	csp := sw.CSP{KeyImporters: keyImporters}
	value, err := csp.KeyImport(expectedRaw, expectedOpts)
	require.Nil(t, value)
	require.Contains(t, err.Error(), expectedErr.Error())

	keyImporters = make(map[reflect.Type]sw.KeyImporter)
	keyImporters[reflect.TypeOf(&mocks2.KeyDerivOpts{})] = &mocks.KeyImporter{
		RawArg:  expectedRaw,
		OptsArg: expectedOpts,
		Value:   expectetValue,
		Err:     nil,
	}
	csp = sw.CSP{KeyImporters: keyImporters}
	value, err = csp.KeyImport(expectedRaw, expectedOpts)
	require.Equal(t, expectetValue, value)
	require.Nil(t, err)
}

func TestSM4ImportKeyOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := sm4ImportKeyOptsKeyImporter{}

	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport([]byte(nil), &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. It must not be nil.")

	_, err = ki.KeyImport([]byte{0}, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid Key Length [")
}

func TestSM2PKIXPublicKeyImportOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := sm2PKIXPublicKeyImportOptsKeyImporter{}


	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport([]byte(nil), &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw. It must not be nil.")

	_, err = ki.KeyImport([]byte{0}, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Failed converting PKIX to SM2 public key [")

	sk, err := sm2.GenerateKey(rand.Reader)
	//fmt.Println(sk.PublicKey)
	require.NoError(t, err)

	//raw,err:=sm2.MarshalSM2PublicKey(&sk.PublicKey)
	raw,err:=publicKeyToDER(&sk.PublicKey)
	//fmt.Println(raw)
	_, err = ki.KeyImport(raw, &mocks2.KeyImportOpts{})
	require.NoError(t, err)

	//x509.ParsePKIXPublicKey(raw)中的parsePublicKey函数中我使用了ECDSA的身份作为SM2的身份了所以SM2的公钥无法解析
	//require.Contains(t, err.Error(), "Failed casting to SM2 public key. Invalid raw material.")
}

func TestSM2KeyGenAndImport(t *testing.T){
	kg := &sm2KeyGenerator{curve:sm2.P256()}

	k, err := kg.KeyGen(nil)
	require.NoError(t, err)

	sm2K, ok := k.(*sm2PrivateKey)

	require.True(t, ok)

	ki := sm2PrivateKeyImportOptsKeyImporter{}
	raw,err:=x509.MarshalPKISM2PrivateKey(sm2K.privKey,nil)
	_, err = ki.KeyImport(raw, &mocks2.KeyImportOpts{})
	require.NoError(t, err)
}


func TestSM2PrivateKeyImportOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := sm2PrivateKeyImportOptsKeyImporter{}

	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport([]byte(nil), &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw. It must not be nil.")

	_, err = ki.KeyImport([]byte{0}, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Failed converting PKIX to SM2 public key")

	k, err := sm2.GenerateKey(rand.Reader)
	require.NoError(t, err)
	raw,err:=x509.MarshalPKISM2PrivateKey(k,nil)
	_, err = ki.KeyImport(raw, &mocks2.KeyImportOpts{})
	require.NoError(t, err)

	//require.Contains(t, err.Error(), "Failed casting to SM2 private key. Invalid raw material.")
}

func TestSM2GoPublicKeyImportOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := sm2GoPublicKeyImportOptsKeyImporter{}

	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected *ecdsa.PublicKey.")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected *ecdsa.PublicKey.")
}

//func TestHMACImportKeyOptsKeyImporter(t *testing.T) {
//	t.Parallel()
//
//	ki := hmacImportKeyOptsGMKeyImporter{}
//
//	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
//	require.Error(t, err)
//	require.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")
//
//	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
//	require.Error(t, err)
//	require.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")
//
//	_, err = ki.KeyImport([]byte(nil), &mocks2.KeyImportOpts{})
//	require.Error(t, err)
//	require.Contains(t, err.Error(), "Invalid raw material. It must not be nil.")
//}

func TestX509PublicKeyImportOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := x509PublicKeyImportOptsGMKeyImporter{}

	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected *x509.Certificate.")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid raw material. Expected *x509.Certificate.")

	//cert := &x509.Certificate{}

	//cert.PublicKey = "Hello world"  //原先的程序是接口类型,所以可以随意赋值,现在是*sm2.Public类型
	//pub,err:=sm2.RawBytesToPublicKey([]byte("Hello world"))

	//pub,err:=sm2.ParseSM2PublicKey([]byte("Hello world"))
	//sm2.RawBytesToPrivateKey([]byte("Hello world"))
	//pub:=sm2.Decompress([]byte("Hello world"))
	//priv,err:=sm2.GenerateKey(rand.Reader)
	//pub:=&priv.PublicKey
	//cert.PublicKey=pub

	//fmt.Println(pub)
	//_, err = ki.KeyImport(cert, &mocks2.KeyImportOpts{})
	//require.Error(t, err)
	//require.Contains(t, err.Error(), "Certificate's public key type not recognized. Supported keys: [ECDSA, RSA]")
}

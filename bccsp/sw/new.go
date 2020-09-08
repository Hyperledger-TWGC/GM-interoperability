/*
Copyright Hyperledger - Technical Working Group China. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sw

import (
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm3"
	"github.com/hyperledger/fabric/bccsp"
	gmbccsp "github.com/Hyperledger-TWGC/fabric-gm-plugins/bccsp"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/pkg/errors"
	"reflect"
)

// NewDefaultSecurityLevel returns a new instance of the software-based BCCSP
// at security level 256, hash family SM3 and using FolderBasedKeyStore as KeyStore.
func NewDefaultSecurityLevel(keyStorePath string) (bccsp.BCCSP, error) {
	ks := &fileBasedKeyStore{}
	if err := ks.Init(nil, keyStorePath, false); err != nil {
		return nil, errors.Wrapf(err, "Failed initializing key store at [%v]", keyStorePath)
	}

	return NewWithParams(256, "SM3", ks)
}

// NewDefaultSecurityLevel returns a new instance of the software-based BCCSP
func NewDefaultSecurityLevelWithKeystore(keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	return NewWithParams(256, "SM3", keyStore)
}

func NewWithParams(securityLevel int, hashFamily string, keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	// Init config
	conf := &config{}
	err := conf.setSecurityLevel(securityLevel, hashFamily)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed initializing configuration at [%v,%v]", securityLevel, hashFamily)
	}

	swbccsp, err := sw.New(keyStore)
	if err != nil {
		return nil, err
	}

	// Notice that errors are ignored here because some test will fail if one
	// of the following call fails.
	swbccsp.AddWrapper(reflect.TypeOf(&sm4PrivateKey{}), &sm4cbcpkcs7Encryptor{})


	// Set the Decryptors
	swbccsp.AddWrapper(reflect.TypeOf(&sm4PrivateKey{}), &sm4cbcpkcs7Decryptor{})

	// Set the Signers
	swbccsp.AddWrapper(reflect.TypeOf(&sm2PrivateKey{}), &sm2Signer{})


	// Set the Verifiers
	swbccsp.AddWrapper(reflect.TypeOf(&sm2PrivateKey{}), &sm2PrivateKeyVerifier{})
	swbccsp.AddWrapper(reflect.TypeOf(&sm2PublicKey{}), &sm2PublicKeyKeyVerifier{})

	// Set the Hashers
	//swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM3Opts{}), &hasher{hash: conf.hashFunction})
	swbccsp.AddWrapper(reflect.TypeOf(&gmbccsp.SM3Opts{}), &hasher{hash: sm3.New})

	// Set the key generators
	swbccsp.AddWrapper(reflect.TypeOf(&gmbccsp.SM2KeyGenOpts{}), &sm2KeyGenerator{curve: conf.ellipticCurve})
	swbccsp.AddWrapper(reflect.TypeOf(&gmbccsp.SM4KeyGenOpts{}), &sm4KeyGenerator{length: conf.aesBitLength}) //!

	// Set the key generators
	swbccsp.AddWrapper(reflect.TypeOf(&sm2PrivateKey{}), &sm2PrivateKeyKeyDeriver{})
	swbccsp.AddWrapper(reflect.TypeOf(&sm2PublicKey{}), &sm2PublicKeyKeyDeriver{})
	swbccsp.AddWrapper(reflect.TypeOf(&sm4PrivateKey{}), &sm4PrivateKeyKeyDeriver{conf: conf})


	// Set the key importers
	swbccsp.AddWrapper(reflect.TypeOf(&gmbccsp.SM4ImportKeyOpts{}), &sm4ImportKeyOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&gmbccsp.SM2PKIXPublicKeyImportOpts{}), &sm2PKIXPublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&gmbccsp.SM2PrivateKeyImportOpts{}), &sm2PrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&gmbccsp.SM2GoPublicKeyImportOpts{}), &sm2GoPublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&gmbccsp.X509PublicKeyImportOpts{}), &x509PublicKeyImportOptsGMKeyImporter{bccsp: swbccsp})

	return swbccsp, nil
}


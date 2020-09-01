/*
Copyright Hyperledger - Technical Working Group China. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sw

import (
	"crypto/x509"
	"errors"
	"fmt"
	gmbccsp "github.com/Hyperledger-TWGC/fabric-gm-plugins/bccsp"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm2"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/sw"
	"reflect"
)

type sm4ImportKeyOptsKeyImporter struct{}

func (*sm4ImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	sm4Raw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if sm4Raw == nil {
		return nil, errors.New("Invalid raw material. It must not be nil.")
	}

	if len(sm4Raw) != 32 {
		return nil, fmt.Errorf("Invalid Key Length [%d]. Must be 32 bytes", len(sm4Raw))
	}

	return &sm4PrivateKey{sm4Raw, false}, nil
}



type sm2PKIXPublicKeyImportOptsKeyImporter struct{}

func (*sm2PKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	der, ok := raw.([]byte)

	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	sm2PK,err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to SM2 public key [%s]", err)
	}

	//if !ok {
	//	return nil, errors.New("Failed casting to SM2public key. Invalid raw material.")
	//}

	return &sm2PublicKey{sm2PK}, nil
}

type sm2PrivateKeyImportOptsKeyImporter struct{}

func (*sm2PrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[SM2DERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[SM2DERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}



	sm2SK,err:=derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to SM2 public key [%s]", err)
	}

	if !ok {
		return nil, errors.New("Failed casting to SM2 private key. Invalid raw material.")
	}
	return &sm2PrivateKey{sm2SK}, nil
}

type sm2GoPublicKeyImportOptsKeyImporter struct{}

func (*sm2GoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {

	lowLevelKey, ok := raw.(*sm2.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *ecdsa.PublicKey.")
	}

	return &sm2PublicKey{lowLevelKey}, nil
}

type x509PublicKeyImportOptsGMKeyImporter struct {
	bccsp *sw.CSP
}

func (ki *x509PublicKeyImportOptsGMKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	x509Cert, ok := raw.(*x509.Certificate)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *x509.Certificate.")
	}

	pk := x509Cert.PublicKey


	switch pk.(type) {
	case *sm2.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&gmbccsp.SM2GoPublicKeyImportOpts{})].KeyImport(
			pk,
			&gmbccsp.SM2GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	default:
		return nil, errors.New("Certificate's public key type not recognized. Supported keys: [SM2]")
	}

}

type hmacImportKeyOptsGMKeyImporter struct{}

func (*hmacImportKeyOptsGMKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	sm4Raw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(sm4Raw) == 0 {
		return nil, errors.New("Invalid raw material. It must not be nil.")
	}

	return &sm4PrivateKey{sm4Raw, false}, nil
}
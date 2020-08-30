package sw

import (

	"errors"
	"fmt"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/bccsp"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm2"
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

//type hmacImportKeyOptsGMKeyImporter struct{}
//
//func (*hmacImportKeyOptsGMKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
//	aesRaw, ok := raw.([]byte)
//	if !ok {
//		return nil, errors.New("Invalid raw material. Expected byte array.")
//	}
//
//	if len(aesRaw) == 0 {
//		return nil, errors.New("Invalid raw material. It must not be nil.")
//	}
//
//	return &sm4PrivateKey{utils.Clone(aesRaw), false}, nil
//}

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

	if !ok {
		return nil, errors.New("Failed casting to SM2public key. Invalid raw material.")
	}

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
	fmt.Println("123456")
	lowLevelKey, ok := raw.(*sm2.PublicKey)
	fmt.Println("lowLevelKey",lowLevelKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *ecdsa.PublicKey.")
	}
	//fmt.Println("lowLevelKey",lowLevelKey)

	return &sm2PublicKey{lowLevelKey}, nil
}

type x509PublicKeyImportOptsGMKeyImporter struct {
	bccsp *CSP
}
//
func (ki *x509PublicKeyImportOptsGMKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	x509Cert, ok := raw.(*x509.Certificate)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *x509.Certificate.")
	}

	pk := x509Cert.PublicKey


	return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.SM2GoPublicKeyImportOpts{})].KeyImport(
		pk,
		&bccsp.SM2GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})

}


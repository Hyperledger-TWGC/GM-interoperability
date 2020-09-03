package tjfoc_gm

import (
	"encoding/pem"
	"errors"

	//"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm2"
	tjfoc_gm_x509 "github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	tjfoc_gm_sm2 "github.com/Hyperledger-TWGC/tjfoc-gm/sm2"

)

func MarshalPKISM2PublicKey(key *PublicKey) ([]byte, error){

	pub:=tjfoc_gm_sm2.PublicKey{}
	pub.X=key.X
	pub.Y=key.Y
	pub.Curve=key.Curve
	return tjfoc_gm_x509.MarshalSm2PublicKey(&pub)
}

func MarshalPKISM2PrivateKey(key *PrivateKey, pwd []byte) ([]byte, error) {

	priv:=tjfoc_gm_sm2.PrivateKey{}
	priv.X=key.X
	priv.Y=key.Y
	priv.D=key.D
	priv.Curve=key.Curve
	return tjfoc_gm_x509.MarshalSm2PrivateKey(&priv,pwd)
}
func MarshalECSM2PrivateKey(key *PrivateKey) ([]byte,error){
	priv:=tjfoc_gm_sm2.PrivateKey{}
	priv.X=key.X
	priv.Y=key.Y
	priv.D=key.D
	priv.Curve=key.Curve
	return tjfoc_gm_x509.MarshalSm2UnecryptedPrivateKey(&priv)
}
func ParsePKISM2PrivateKey(der []byte) (*PrivateKey, error) {
	pirv,err:=tjfoc_gm_x509.ParseSm2PrivateKey(der)
	if err != nil{
		return nil, err
	}
	key:=PrivateKey{}
	key.X=pirv.X
	key.Y=pirv.Y
	key.D=pirv.D
	key.Curve=pirv.Curve
	return &key,err

}

func ParsePKCS8PrivateKey(der, pwd []byte) (*PrivateKey, error) {
	pirv,err:=tjfoc_gm_x509.ParsePKCS8PrivateKey(der,pwd)
	if err != nil{
		return nil, err
	}
	key:=PrivateKey{}
	key.X=pirv.X
	key.Y=pirv.Y
	key.D=pirv.D
	key.Curve=pirv.Curve
	return &key,err

}
func ParsePKCS8EcryptedPrivateKey(der, pwd []byte) (*PrivateKey, error) {

	pirv,err:=tjfoc_gm_x509.ParsePKCS8EcryptedPrivateKey(der,pwd)
	if err != nil{
		return nil, err
	}
	key:=PrivateKey{}
	key.X=pirv.X
	key.Y=pirv.Y
	key.D=pirv.D
	key.Curve=pirv.Curve
	return &key,err
}
func ParsePKISM2PublicKey(der []byte) (*PublicKey, error) {

	pub,err:=tjfoc_gm_x509.ParseSm2PublicKey(der)
	if err != nil{
		return nil, err
	}
	key:=PublicKey{}
	key.X=pub.X
	key.Y=pub.Y
	key.Curve=pub.Curve
	return &key,err

}


func WritePrivateKeytoMem(key *PrivateKey, pwd []byte) ([]byte, error) {
	priv:=tjfoc_gm_sm2.PrivateKey{}
	priv.X=key.X
	priv.Y=key.Y
	priv.D=key.D
	priv.Curve=key.Curve

	return writePrivateKeytoMem(&priv,pwd)
}

func WritePrivateKeytoPem(FileName string, key *PrivateKey, pwd []byte) ([]byte,error) {
	priv:=tjfoc_gm_sm2.PrivateKey{}
	priv.X=key.X
	priv.Y=key.Y
	priv.D=key.D
	priv.Curve=key.Curve
	return tjfoc_gm_x509.WritePrivateKeytoPem(&priv,pwd)
}


func WritePublicKeytoMem(key *PublicKey) ([]byte, error) {
	pub:=tjfoc_gm_sm2.PublicKey{}
	pub.X=key.X
	pub.Y=key.Y
	pub.Curve=key.Curve
	return writePublicKeytoMem(&pub)

}


func WritePublicKeytoPem(FileName string, key *PublicKey) (err error) {
	pub:=tjfoc_gm_sm2.PublicKey{}
	pub.X=key.X
	pub.Y=key.Y
	pub.Curve=key.Curve
	return tjfoc_gm_x509.WritePublicKeytoPem(FileName,&pub)
}


func ReadPrivateKeyFromMem(data []byte, pwd []byte) (*PrivateKey, error) {
	pirv,err:=readPrivateKeyFromMem(data,pwd)
	if err != nil{
		return nil, err
	}
	key:=PrivateKey{}
	key.X=pirv.X
	key.Y=pirv.Y
	key.D=pirv.D
	key.Curve=pirv.Curve
	return &key,err
}


func ReadPrivateKeyFromPem(FileName string, pwd []byte) (*PrivateKey, error) {
	pirv,err:=tjfoc_gm_x509.ReadPrivateKeyFromPem(FileName,pwd)
	if err != nil{
		return nil, err
	}
	key:=PrivateKey{}
	key.X=pirv.X
	key.Y=pirv.Y
	key.D=pirv.D
	key.Curve=pirv.Curve
	return &key,err
}


func ReadPublicKeyFromMem(data []byte) (*PublicKey, error) {
	pub,err:=readPublicKeyFromMem(data)
	if err != nil{
		return nil, err
	}
	key:=PublicKey{}
	key.X=pub.X
	key.Y=pub.Y
	key.Curve=pub.Curve
	return &key,err
}





func ReadPublicKeyFromPem(FileName string) (*PublicKey, error) {
	pub,err:=tjfoc_gm_x509.ReadPublicKeyFromPem(FileName)
	if err != nil{
		return nil, err
	}
	key:=PublicKey{}
	key.X=pub.X
	key.Y=pub.Y
	key.Curve=pub.Curve
	return &key,err

}

//----------------------------------------------------------------//
func readPrivateKeyFromMem(data []byte, pwd []byte) (*tjfoc_gm_sm2.PrivateKey, error) {
	var block *pem.Block

	block, _ = pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode private key")
	}
	priv, err := tjfoc_gm_x509.ParsePKCS8PrivateKey(block.Bytes, pwd)
	return priv, err
}


func writePublicKeytoMem(key *tjfoc_gm_sm2.PublicKey) ([]byte, error) {
	der, err := tjfoc_gm_x509.MarshalSm2PublicKey(key)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}


func readPublicKeyFromMem(data []byte) (*tjfoc_gm_sm2.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode public key")
	}
	pub, err := tjfoc_gm_x509.ParseSm2PublicKey(block.Bytes)
	return pub, err
}


func writePrivateKeytoMem(key *tjfoc_gm_sm2.PrivateKey, pwd []byte) ([]byte, error) {
	var block *pem.Block

	der, err := tjfoc_gm_x509.MarshalSm2PrivateKey(key, pwd)
	if err != nil {
		return nil, err
	}
	if pwd != nil {
		block = &pem.Block{
			Type:  "ENCRYPTED PRIVATE KEY",
			Bytes: der,
		}
	} else {
		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}
	}
	return pem.EncodeToMemory(block), nil
}




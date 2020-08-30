package tjfoc_gm

import (

	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm2"
	tjfoc_gm_x509 "github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	tjfoc_gm_sm2 "github.com/Hyperledger-TWGC/tjfoc-gm/sm2"

)

func MarshalPKISM2PublicKey(key *sm2.PublicKey) ([]byte, error){

	pub:=tjfoc_gm_sm2.PublicKey{}
	pub.X=key.X
	pub.Y=key.Y
	pub.Curve=key.Curve
	return tjfoc_gm_x509.MarshalSm2PublicKey(pub)
}

func MarshalPKISM2PrivateKey(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {

	return tjfoc_gm_x509.MarshalSm2PrivateKey(key,pwd)
}
func MarshalECSM2PrivateKey(key *sm2.PrivateKey) ([]byte,error){
	return tjfoc_gm_x509.MarshalSm2UnecryptedPrivateKey(key)
}
func ParsePKISM2PrivateKey(der []byte) (*sm2.PrivateKey, error) {
	return tjfoc_gm_x509.ParseSm2PrivateKey(der)
}


func ParsePKISM2PublicKey(der []byte) (*sm2.PublicKey, error) {

	return tjfoc_gm_x509.ParseSm2PublicKey(der)
}


func WritePrivateKeytoMem(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	return WritePrivateKeytoMem(key)
}

func WritePrivateKeytoPem(FileName string, key *sm2.PrivateKey, pwd []byte) (err error) {

}


func WritePublicKeytoMem(key *sm2.PublicKey) ([]byte, error) {

}


func WritePublicKeytoPem(FileName string, key *sm2.PublicKey) (err error) {

}


func ReadPrivateKeyFromMem(data []byte, pwd []byte) (*sm2.PrivateKey, error) {

}


func ReadPrivateKeyFromPem(FileName string, pwd []byte) (*sm2.PrivateKey, error) {

}


func ReadPublicKeyFromMem(data []byte) (*sm2.PublicKey, error) {
}


func ReadPublicKeyFromPem(FileName string) (*sm2.PublicKey, error) {
}












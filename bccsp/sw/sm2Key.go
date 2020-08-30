package sw

import (
	"errors"
	"fmt"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/bccsp"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm2"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm3"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/x509"
)

//type SM2PrivateKey struct {
//	SM2PrivateKey  sm2PrivateKey
//}

type sm2PrivateKey struct {
	privKey *sm2.PrivateKey
}




// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *sm2PrivateKey) Bytes() ([]byte,error) {
	return nil,errors.New("Not supported")
}


// SKI returns the subject key identifier of this key.
func (k *sm2PrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}

	// Marshall the public key
	//raw := elliptic.Marshal(k.privKey.Curve,k.privKey.PublicKey.X, k.privKey.PublicKey.Y)
	//raw := k.privKey.GetRawBytes()
	raw,_ := x509.MarshalPKISM2PrivateKey(k.privKey,nil)
	// Hash it
	hash := sm3.New()
	hash.Write(raw)
	return hash.Sum(nil)
}


func (k *sm2PrivateKey) Symmetric() bool {
	return false
}

func (k *sm2PrivateKey) Private() bool {
	return true
}

func (k *sm2PrivateKey) PublicKey() (bccsp.Key,error) {
	return &sm2PublicKey{&k.privKey.PublicKey},nil
}




type sm2PublicKey struct {
	pubKey *sm2.PublicKey
}


func (k *sm2PublicKey) Bytes() (raw []byte,err error) {

	raw,err = x509.MarshalPKISM2PublicKey(k.pubKey)
	if err != nil {
		return nil,fmt.Errorf("Failed marshalling key [%s]",err)
	}
	return
}

func (k *sm2PublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}
	raw,_ := x509.MarshalPKISM2PublicKey(k.pubKey)
	hash := sm3.New()
	hash.Write(raw)
	return hash.Sum(nil)
}



func (k *sm2PublicKey) Symmetric() bool {
	return false
}

func (k *sm2PublicKey) Private() bool {
	return false
}

func (k *sm2PublicKey) PublicKey() (bccsp.Key,error) {
	return k,nil
}

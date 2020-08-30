package sw

import (
	"crypto/rand"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/bccsp"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm2"
	//"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm2"
)



func signSM2(k *sm2.PrivateKey,digest []byte,opts bccsp.SignerOpts) ([]byte,error) {
	r,err := k.Sign(rand.Reader,digest)

	if err != nil {
		return nil,err
	}
	return r, err

}


func verifySM2(k *sm2.PublicKey,signature,digest []byte,opts bccsp.SignerOpts) (bool,error) {
	result := k.Verify(digest,signature)

	if !result  {
		return false,nil
	}


	return result,nil
}


type sm2Signer struct {}

func (s *sm2Signer) Sign(k bccsp.Key,digest []byte,opts bccsp.SignerOpts)  ([]byte, error) {
	return signSM2(k.(*sm2PrivateKey).privKey,digest,opts)
}

type sm2PrivateKeyVerifier struct{}


func (v *sm2PrivateKeyVerifier) Verify(k bccsp.Key,signature,digest []byte,opts bccsp.SignerOpts) (bool,error) {

	return verifySM2(&(k.(*sm2PrivateKey).privKey.PublicKey),signature,digest,opts)
}


type sm2PublicKeyKeyVerifier struct {

}

func (v *sm2PublicKeyKeyVerifier) Verify(k bccsp.Key,signature,digest []byte,opts bccsp.SignerOpts) (bool,error) {
	return verifySM2(k.(*sm2PublicKey).pubKey,signature,digest,opts)

}
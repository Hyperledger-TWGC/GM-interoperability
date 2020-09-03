/*
Copyright Hyperledger - Technical Working Group China. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sw

import (
	"fmt"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/bccsp/utils"
	"github.com/hyperledger/fabric/bccsp"

	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm2"
	//"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm2"
)



func signSM2(k *sm2.PrivateKey,digest []byte,opts bccsp.SignerOpts) ([]byte,error) {
	r,err := k.Sign(digest,nil)

	if err != nil {
		return nil,err
	}
	return r, err

}


func verifySM2(k *sm2.PublicKey,signature,digest []byte,opts bccsp.SignerOpts) (bool,error) {
	_, s, err := utils.UnmarshalSM2Signature(signature)
	if err != nil {
		return false, fmt.Errorf("Failed unmashalling signature [%s]", err)
	}

	lowS, err := utils.SM2IsLowS(k, s)
	if err != nil {
		return false, err
	}

	fmt.Println(lowS)
	//if !lowS {
	//	return false, fmt.Errorf("Invalid S. Must be smaller than half the order [%s][%s].", s, utils.GetCurveHalfOrdersAtSM2(k.Curve))
	//}


	return k.Verify(digest,signature),nil
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
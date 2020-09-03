package utils

import (
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm2"
	"math/big"
)

type SM2Signature struct {
	R,S *big.Int
}


func MarshalSM2Signature(r,s *big.Int) ([]byte,error)  {


	return asn1.Marshal(SM2Signature{r,s})


}

func UnmarshalSM2Signature(raw []byte) (*big.Int,*big.Int, error) {
	// Unmarshal
	sig := new(SM2Signature)
	_, err := asn1.Unmarshal(raw, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed unmashalling signature [%s]", err)
	}

	// Validate sig
	if sig.R == nil {
		return nil, nil, errors.New("invalid signature, R must be different from nil")
	}
	if sig.S == nil {
		return nil, nil, errors.New("invalid signature, S must be different from nil")
	}

	if sig.R.Sign() != 1 {
		return nil, nil, errors.New("invalid signature, R must be larger than zero")
	}
	if sig.S.Sign() != 1 {
		return nil, nil, errors.New("invalid signature, S must be larger than zero")
	}

	return sig.R, sig.S, nil
}



func SM2SignatureToLowS(k *sm2.PublicKey, signature []byte) ([]byte, error) {


	r, s, err := UnmarshalSM2Signature(signature)
	if err != nil {
		return nil, err
	}

	s, modified, err := SM2ToLowS(k, s)
	if err != nil {
		return nil, err
	}

	if modified {
		return MarshalSM2Signature(r, s)
	}

	return signature, nil
}




var (

	sm2curveHalfOrders = map[elliptic.Curve]*big.Int{
		sm2.P256():   new(big.Int).Rsh(sm2.P256().Params().N, 1),
	}
)

func GetCurveHalfOrdersAtSM2(c elliptic.Curve) *big.Int {
	return big.NewInt(0).Set(sm2curveHalfOrders[c])
}
// IsLow checks that s is a low-S
func SM2IsLowS(k *sm2.PublicKey, s *big.Int) (bool, error) {
	halfOrder, ok := sm2curveHalfOrders[k.Curve]
	if !ok {
		return false, fmt.Errorf("curve not recognized [%s]", k.Curve)
	}
	return s.Cmp(halfOrder) != 1, nil

}

func SM2ToLowS(k *sm2.PublicKey, s *big.Int) (*big.Int, bool, error) {
	lowS, err := SM2IsLowS(k, s)
	if err != nil {
		return nil, false, err
	}

	if !lowS {
		// Set s to N - s that will be then in the lower part of signature space
		// less or equal to half order
		//s.Sub(k.Params().N, s)
		s.Sub(k.Curve.Params().N,s) //瞎写的

		return s, true, nil
	}

	return s, false, nil
}


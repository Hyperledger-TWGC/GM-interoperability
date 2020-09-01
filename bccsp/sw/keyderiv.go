/*
Copyright Hyperledger - Technical Working Group China. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sw

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"github.com/hyperledger/fabric/bccsp"
	gmbccsp "github.com/Hyperledger-TWGC/fabric-gm-plugins/bccsp"

	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm2"

	"math/big"
)

type sm2PublicKeyKeyDeriver struct{}

func (kd *sm2PublicKeyKeyDeriver) KeyDeriv(key bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	// Validate opts

	if opts == nil {
		return nil, errors.New("Invalid opts parameter. It must not be nil.")
	}

	sm2K := key.(*sm2PublicKey)

	switch opts.(type) {
	// Re-randomized an SM2 private key
	case *gmbccsp.SM2ReRandKeyOpts:
		reRandOpts := opts.(*gmbccsp.SM2ReRandKeyOpts)



		tempSK := &sm2.PublicKey{
			Curve: sm2K.pubKey.Curve,
			X:     new(big.Int),
			Y:     new(big.Int),
		}

		var k = new(big.Int).SetBytes(reRandOpts.ExpansionValue())
		var one = new(big.Int).SetInt64(1)
		n := new(big.Int).Sub(sm2K.pubKey.Curve.Params().N, one)
		k.Mod(k, n)
		k.Add(k, one)

		// Compute temporary public key
		tempX, tempY := sm2K.pubKey.Curve.ScalarBaseMult(k.Bytes())

		tempSK.X, tempSK.Y = tempSK.Curve.Add(
			sm2K.pubKey.X, sm2K.pubKey.Y,
			tempX, tempY,
		)

		// Verify temporary public key is a valid point on the reference curve
		isOn := tempSK.Curve.IsOnCurve(tempSK.X, tempSK.Y)
		if !isOn {
			return nil, errors.New("Failed temporary public key IsOnCurve check.")
		}

		return &sm2PublicKey{tempSK}, nil
	default:
		return nil, fmt.Errorf("Unsupported 'KeyDerivOpts' provided [%v]", opts)
	}
}


type sm2PrivateKeyKeyDeriver struct {}

func (kd *sm2PrivateKeyKeyDeriver) KeyDeriv(key bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	// Validate opts
	if opts == nil {
		return nil, errors.New("Invalid opts parameter. It must not be nil.")
	}

	sm2K := key.(*sm2PrivateKey)

	switch opts.(type) {



	// Re-randomized an SM2 private key
	case *gmbccsp.SM2ReRandKeyOpts:
		reRandOpts := opts.(*gmbccsp.SM2ReRandKeyOpts)



		tempSK := &sm2.PrivateKey{
			PublicKey:sm2.PublicKey{
				Curve: sm2K.privKey.Curve,
				X:     new(big.Int),
				Y:     new(big.Int),
			},
			D: new(big.Int),
		}


		var k = new(big.Int).SetBytes(reRandOpts.ExpansionValue())
		var one = new(big.Int).SetInt64(1)
		n := new(big.Int).Sub(sm2K.privKey.Params().N, one)
		k.Mod(k, n)
		k.Add(k, one)

		tempSK.D.Add(sm2K.privKey.D, k)
		tempSK.D.Mod(tempSK.D, sm2K.privKey.PublicKey.Params().N)
		// Compute temporary public key
		tempX, tempY := sm2K.privKey.Curve.ScalarBaseMult(k.Bytes())
		tempSK.X, tempSK.Y = tempSK.Curve.Add(
			sm2K.privKey.X, sm2K.privKey.Y,
			tempX, tempY,
		)

		// Verify temporary public key is a valid point on the reference curve
		isOn := tempSK.Curve.IsOnCurve(tempSK.X, tempSK.Y)
		if !isOn {
			return nil, errors.New("Failed temporary public key IsOnCurve check.")
		}

		return &sm2PrivateKey{tempSK}, nil
	default:
		return nil, fmt.Errorf("Unsupported 'KeyDerivOpts' provided [%v]", opts)
	}
}


type sm4PrivateKeyKeyDeriver struct {
	conf *config
}

func (kd *sm4PrivateKeyKeyDeriver) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	// Validate opts
	if opts == nil {
		return nil, errors.New("Invalid opts parameter. It must not be nil.")
	}

	sm4K := k.(*sm4PrivateKey)
	switch hmacOpts := opts.(type) {
	case *gmbccsp.HMACTruncated256SM4DeriveKeyOpts:
		mac := hmac.New(kd.conf.hashFunction, sm4K.privKey)
		mac.Write(hmacOpts.Argument())
		return &sm4PrivateKey{mac.Sum(nil)[:kd.conf.aesBitLength], false}, nil

	case *bccsp.HMACDeriveKeyOpts:
		mac := hmac.New(kd.conf.hashFunction, sm4K.privKey)
		mac.Write(hmacOpts.Argument())
		return &sm4PrivateKey{mac.Sum(nil), true}, nil
	default:
		return nil, fmt.Errorf("Unsupported 'KeyDerivOpts' provided [%v]", opts)
	}
}



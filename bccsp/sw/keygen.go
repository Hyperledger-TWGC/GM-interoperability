/*
Copyright Hyperledger - Technical Working Group China. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sw

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/hyperledger/fabric/bccsp"

	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm2"
)

type sm2KeyGenerator struct {
	curve elliptic.Curve
}

func (kg *sm2KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Failed generating SM2 key for [%v]: [%s]", kg.curve, err)
	}

	return &sm2PrivateKey{privKey}, nil
}

type sm4KeyGenerator struct {
	length int
}

func (kg *sm4KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	lowLevelKey, err := GetRandomBytes(int(kg.length))
	if err != nil {
		return nil, fmt.Errorf("Failed generating SM4 %d key [%s]", kg.length, err)
	}

	return &sm4PrivateKey{lowLevelKey, false}, nil
}



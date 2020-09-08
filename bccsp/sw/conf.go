/*
Copyright Hyperledger - Technical Working Group China. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sw

import (
	"crypto/elliptic"
	"fmt"
	common_sm3 "github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm3"
	common_sm2 "github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm2"

	"hash"
)

type config struct {
	ellipticCurve elliptic.Curve
	hashFunction  func() hash.Hash
	aesBitLength  int
	rsaBitLength  int
}

func (conf *config) setSecurityLevel(securityLevel int, hashFamily string) (err error) {

	if hashFamily =="SM3" {
		err = conf.setSecurityLevelSM3(securityLevel)
	}else{
		err = fmt.Errorf("Hash Family not supported [%s]", hashFamily)
	}
	return

}

func (conf *config) setSecurityLevelSM3(level int) (err error) {

	switch level {
	case 256:
		conf.ellipticCurve = common_sm2.P256()
		conf.hashFunction = common_sm3.New
		conf.rsaBitLength = 2048
		conf.aesBitLength = 16
	default:
		err = fmt.Errorf("Security level not supported [%d]", level)
	}

	return
}


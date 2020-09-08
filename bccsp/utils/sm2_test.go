package utils

import (
	"crypto/rand"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm2"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestUnmarshalSM2Signature(t *testing.T) {
	_, _, err := UnmarshalSM2Signature(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed unmashalling signature [")

	_, _, err = UnmarshalSM2Signature([]byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed unmashalling signature [")

	_, _, err = UnmarshalSM2Signature([]byte{0})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed unmashalling signature [")

	sigma, err := MarshalSM2Signature(big.NewInt(-1), big.NewInt(1))
	assert.NoError(t, err)
	_, _, err = UnmarshalSM2Signature(sigma)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature, R must be larger than zero")

	sigma, err = MarshalSM2Signature(big.NewInt(0), big.NewInt(1))
	assert.NoError(t, err)
	_, _, err = UnmarshalSM2Signature(sigma)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature, R must be larger than zero")

	sigma, err = MarshalSM2Signature(big.NewInt(1), big.NewInt(0))
	assert.NoError(t, err)
	_, _, err = UnmarshalSM2Signature(sigma)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature, S must be larger than zero")

	sigma, err = MarshalSM2Signature(big.NewInt(1), big.NewInt(-1))
	assert.NoError(t, err)
	_, _, err = UnmarshalSM2Signature(sigma)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature, S must be larger than zero")

	sigma, err = MarshalSM2Signature(big.NewInt(1), big.NewInt(1))
	assert.NoError(t, err)
	R, S, err := UnmarshalSM2Signature(sigma)
	assert.NoError(t, err)
	assert.Equal(t, big.NewInt(1), R)
	assert.Equal(t, big.NewInt(1), S)
}



func TestSM2IsLowS(t *testing.T) {

	lowLevelPrivateKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	//lowLevelPrivateKey,lowLevelPublicKey =KeyTransfer(lowLevelPrivateKey,lowLevelPublicKey)

	lowS, err := SM2IsLowS(&lowLevelPrivateKey.PublicKey, big.NewInt(0))
	assert.NoError(t, err)
	assert.True(t, lowS)

	s := new(big.Int)
	s = s.Set(GetCurveHalfOrdersAtSM2(sm2.P256()))

	lowS, err = SM2IsLowS(&lowLevelPrivateKey.PublicKey, s)
	assert.NoError(t, err)
	assert.True(t, lowS)

	s = s.Add(s, big.NewInt(1))
	lowS, err = SM2IsLowS(&lowLevelPrivateKey.PublicKey, s)
	assert.NoError(t, err)
	assert.False(t, lowS)
	s, modified, err := SM2ToLowS(&lowLevelPrivateKey.PublicKey, s)
	assert.NoError(t, err)
	assert.True(t, modified)
	lowS, err = SM2IsLowS(&lowLevelPrivateKey.PublicKey, s)
	assert.NoError(t, err)
	assert.True(t, lowS)
}

func TestSM2SignatureToLowS(t *testing.T) {
	lowLevelPrivateKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	s := new(big.Int)
	s = s.Set(GetCurveHalfOrdersAtSM2(sm2.P256()))
	s = s.Add(s, big.NewInt(1))

	lowS, err := SM2IsLowS(&lowLevelPrivateKey.PublicKey, s)
	assert.NoError(t, err)
	assert.False(t, lowS)
	sigma, err := MarshalSM2Signature(big.NewInt(1), s)
	assert.NoError(t, err)
	sigma2, err := SM2SignatureToLowS(&lowLevelPrivateKey.PublicKey, sigma)
	assert.NoError(t, err)
	_, s, err = UnmarshalSM2Signature(sigma2)
	assert.NoError(t, err)
	lowS, err = SM2IsLowS(&lowLevelPrivateKey.PublicKey, s)
	assert.NoError(t, err)
	assert.True(t, lowS)
}

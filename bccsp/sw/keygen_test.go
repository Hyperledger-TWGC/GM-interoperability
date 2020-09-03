/*
Copyright Hyperledger - Technical Working Group China. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sw

import (
	"errors"
	mocks2 "github.com/Hyperledger-TWGC/fabric-gm-plugins/bccsp/mocks"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/bccsp/sw/mocks"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm2"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/stretchr/testify/require"
	"reflect"
	"testing"
)



func TestKeyGen(t *testing.T) {
	t.Parallel()

	expectedOpts := &mocks2.KeyGenOpts{EphemeralValue: true}
	expectetValue := &mocks2.MockKey{}
	expectedErr := errors.New("Expected Error")

	keyGenerators := make(map[reflect.Type]sw.KeyGenerator)
	keyGenerators[reflect.TypeOf(&mocks2.KeyGenOpts{})] = &mocks.KeyGenerator{
		OptsArg: expectedOpts,
		Value:   expectetValue,
		Err:     expectedErr,
	}
	csp := sw.CSP{KeyGenerators: keyGenerators}
	value, err := csp.KeyGen(expectedOpts)
	require.Nil(t, value)
	require.Contains(t, err.Error(), expectedErr.Error())

	keyGenerators = make(map[reflect.Type]sw.KeyGenerator)
	keyGenerators[reflect.TypeOf(&mocks2.KeyGenOpts{})] = &mocks.KeyGenerator{
		OptsArg: expectedOpts,
		Value:   expectetValue,
		Err:     nil,
	}
	csp = sw.CSP{KeyGenerators: keyGenerators}
	value, err = csp.KeyGen(expectedOpts)
	require.Equal(t, expectetValue, value)
	require.Nil(t, err)
}

func TestSM2KeyGenerator(t *testing.T) {
	t.Parallel()

	kg := &sm2KeyGenerator{curve:sm2.P256()}

	k, err := kg.KeyGen(nil)
	require.NoError(t, err)

	sm2K, ok := k.(*sm2PrivateKey)
	
	require.True(t, ok)
	require.NotNil(t, sm2K.privKey)
	require.Equal(t, sm2K.privKey.Curve, sm2.P256())

}



func TestSM4KeyGenerator(t *testing.T) {
	t.Parallel()

	kg := &sm4KeyGenerator{length: 32}

	k, err := kg.KeyGen(nil)
	require.NoError(t, err)

	sm4K, ok := k.(*sm4PrivateKey)
	require.True(t, ok)
	require.NotNil(t, sm4K.privKey)
	require.Equal(t, len(sm4K.privKey), 32)
}

func TestSM4KeyGeneratorInvalidInputs(t *testing.T) {
	t.Parallel()

	kg := &sm4KeyGenerator{length: -1}

	_, err := kg.KeyGen(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Len must be larger than 0")
}


/*
Copyright Hyperledger - Technical Working Group China. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sw

import (
	"errors"
	mocks2 "github.com/Hyperledger-TWGC/fabric-gm-plugins/bccsp/mocks"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/bccsp/sw/mocks"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/stretchr/testify/require"
	"reflect"
	"testing"
)

func TestKeyDeriv(t *testing.T) {
	t.Parallel()

	expectedKey := &mocks2.MockKey{BytesValue: []byte{1, 2, 3}}
	expectedOpts := &mocks2.KeyDerivOpts{EphemeralValue: true}
	expectetValue := &mocks2.MockKey{BytesValue: []byte{1, 2, 3, 4, 5}}
	expectedErr := errors.New("Expected Error")

	keyDerivers := make(map[reflect.Type]sw.KeyDeriver)
	keyDerivers[reflect.TypeOf(&mocks2.MockKey{})] = &mocks.KeyDeriver{
		KeyArg:  expectedKey,
		OptsArg: expectedOpts,
		Value:   expectetValue,
		Err:     expectedErr,
	}
	csp := sw.CSP{KeyDerivers: keyDerivers}
	value, err := csp.KeyDeriv(expectedKey, expectedOpts)
	require.Nil(t, value)
	require.Contains(t, err.Error(), expectedErr.Error())

	keyDerivers = make(map[reflect.Type]sw.KeyDeriver)
	keyDerivers[reflect.TypeOf(&mocks2.MockKey{})] = &mocks.KeyDeriver{
		KeyArg:  expectedKey,
		OptsArg: expectedOpts,
		Value:   expectetValue,
		Err:     nil,
	}
	csp = sw.CSP{KeyDerivers: keyDerivers}
	value, err = csp.KeyDeriv(expectedKey, expectedOpts)
	require.Equal(t, expectetValue, value)
	require.Nil(t, err)
}

func TestSM2PublicKeyKeyDeriver(t *testing.T) {
	t.Parallel()

	kd := sm2PublicKeyKeyDeriver{}

	_, err := kd.KeyDeriv(&mocks2.MockKey{}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid opts parameter. It must not be nil.")

	_, err = kd.KeyDeriv(&sm2PublicKey{}, &mocks2.KeyDerivOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Unsupported 'KeyDerivOpts' provided [")
}


func TestSM2PrivateKeyKeyDeriver(t *testing.T) {
	t.Parallel()

	kd := sm2PrivateKeyKeyDeriver{}

	_, err := kd.KeyDeriv(&mocks2.MockKey{}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid opts parameter. It must not be nil.")

	_, err = kd.KeyDeriv(&sm2PrivateKey{}, &mocks2.KeyDerivOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Unsupported 'KeyDerivOpts' provided [")
}

func TestSM4PrivateKeyKeyDeriver(t *testing.T) {
	t.Parallel()

	kd := sm4PrivateKeyKeyDeriver{}

	_, err := kd.KeyDeriv(&mocks2.MockKey{}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid opts parameter. It must not be nil.")

	_, err = kd.KeyDeriv(&sm4PrivateKey{}, &mocks2.KeyDerivOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Unsupported 'KeyDerivOpts' provided [")
}

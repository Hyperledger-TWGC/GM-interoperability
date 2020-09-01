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

func TestVerify(t *testing.T) {
	t.Parallel()

	expectedKey := &mocks2.MockKey{}
	expectetSignature := []byte{1, 2, 3, 4, 5}
	expectetDigest := []byte{1, 2, 3, 4}
	expectedOpts := &mocks2.SignerOpts{}
	expectetValue := true
	expectedErr := errors.New("Expected Error")

	verifiers := make(map[reflect.Type]sw.Verifier)
	verifiers[reflect.TypeOf(&mocks2.MockKey{})] = &mocks.Verifier{
		KeyArg:       expectedKey,
		SignatureArg: expectetSignature,
		DigestArg:    expectetDigest,
		OptsArg:      expectedOpts,
		Value:        expectetValue,
		Err:          nil,
	}
	csp := sw.CSP{Verifiers: verifiers}
	value, err := csp.Verify(expectedKey, expectetSignature, expectetDigest, expectedOpts)
	require.Equal(t, expectetValue, value)
	require.Nil(t, err)

	verifiers = make(map[reflect.Type]sw.Verifier)
	verifiers[reflect.TypeOf(&mocks2.MockKey{})] = &mocks.Verifier{
		KeyArg:       expectedKey,
		SignatureArg: expectetSignature,
		DigestArg:    expectetDigest,
		OptsArg:      expectedOpts,
		Value:        false,
		Err:          expectedErr,
	}
	csp = sw.CSP{Verifiers: verifiers}
	value, err = csp.Verify(expectedKey, expectetSignature, expectetDigest, expectedOpts)
	require.False(t, value)
	require.Contains(t, err.Error(), expectedErr.Error())
}



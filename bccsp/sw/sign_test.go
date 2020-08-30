package sw

import (
	"errors"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/bccsp/sw/mocks"
	mocks2 "github.com/Hyperledger-TWGC/fabric-gm-plugins/bccsp/mocks"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestSign(t *testing.T) {
	t.Parallel()

	expectedKey := &mocks2.MockKey{}
	expectetDigest := []byte{1, 2, 3, 4}
	expectedOpts := &mocks2.SignerOpts{}
	expectetValue := []byte{0, 1, 2, 3, 4}
	expectedErr := errors.New("Expected Error")

	signers := make(map[reflect.Type]Signer)
	signers[reflect.TypeOf(&mocks2.MockKey{})] = &mocks.Signer{
		KeyArg:    expectedKey,
		DigestArg: expectetDigest,
		OptsArg:   expectedOpts,
		Value:     expectetValue,
		Err:       nil,
	}
	csp := CSP{Signers: signers}
	value, err := csp.Sign(expectedKey, expectetDigest, expectedOpts)
	assert.Equal(t, expectetValue, value)
	assert.Nil(t, err)

	signers = make(map[reflect.Type]Signer)
	signers[reflect.TypeOf(&mocks2.MockKey{})] = &mocks.Signer{
		KeyArg:    expectedKey,
		DigestArg: expectetDigest,
		OptsArg:   expectedOpts,
		Value:     nil,
		Err:       expectedErr,
	}
	csp = CSP{Signers: signers}
	value, err = csp.Sign(expectedKey, expectetDigest, expectedOpts)
	assert.Nil(t, value)
	assert.Contains(t, err.Error(), expectedErr.Error())
}

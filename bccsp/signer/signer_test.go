package signer

import (
	"crypto/rand"
	"errors"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/bccsp/mocks"

	"github.com/stretchr/testify/assert"
	"testing"
)

func TestInitFailures(t *testing.T) {
	_, err := New(nil, &mocks.MockKey{})
	assert.Error(t, err)

	_, err = New(&mocks.MockBCCSP{}, nil)
	assert.Error(t, err)

	_, err = New(&mocks.MockBCCSP{}, &mocks.MockKey{Symm: true})
	assert.Error(t, err)

	_, err = New(&mocks.MockBCCSP{}, &mocks.MockKey{PKErr: errors.New("No PK")})
	assert.Error(t, err)
	assert.Equal(t, "failed getting public key: No PK", err.Error())

	_, err = New(&mocks.MockBCCSP{}, &mocks.MockKey{PK: &mocks.MockKey{BytesErr: errors.New("No bytes")}})
	assert.Error(t, err)
	assert.Equal(t, "failed marshalling public key: No bytes", err.Error())

	_, err = New(&mocks.MockBCCSP{}, &mocks.MockKey{PK: &mocks.MockKey{BytesValue: []byte{0, 1, 2, 3}}})
	assert.Error(t, err)
}

func TestInit(t *testing.T) {
	k, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	//pkRaw, err := utils.PublicKeyToDER(&k.PublicKey)
	pkRaw, err :=  sm2.MarshalSM2PublicKey(&k.PublicKey)
	assert.NoError(t, err)

	signer, err := New(&mocks.MockBCCSP{}, &mocks.MockKey{PK: &mocks.MockKey{BytesValue: pkRaw}})
	assert.NoError(t, err)
	assert.NotNil(t, signer)

	// Test public key
	R, S, err := sm2.SM2Sign(k, []byte{0, 1, 2, 3},nil)
	assert.NoError(t, err)
	assert.True(t, sm2.SM2Verify(&k.PublicKey, []byte{0, 1, 2, 3},nil, R, S))

}



func TestSign(t *testing.T) {
	expectedSig := []byte{0, 1, 2, 3, 4}
	expectedKey := &mocks.MockKey{}
	expectedDigest := []byte{0, 1, 2, 3, 4, 5}
	expectedOpts := &mocks.SignerOpts{}

	signer := &bccspCryptoSigner{
		key: expectedKey,
		csp: &mocks.MockBCCSP{
			SignArgKey: expectedKey, SignDigestArg: expectedDigest, SignOptsArg: expectedOpts,
			SignValue: expectedSig}}
	signature, err := signer.Sign(nil, expectedDigest, expectedOpts)
	assert.NoError(t, err)
	assert.Equal(t, expectedSig, signature)

	signer = &bccspCryptoSigner{
		key: expectedKey,
		csp: &mocks.MockBCCSP{
			SignArgKey: expectedKey, SignDigestArg: expectedDigest, SignOptsArg: expectedOpts,
			SignErr: errors.New("no signature")}}
	signature, err = signer.Sign(nil, expectedDigest, expectedOpts)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "no signature")

	signer = &bccspCryptoSigner{
		key: nil,
		csp: &mocks.MockBCCSP{SignArgKey: expectedKey, SignDigestArg: expectedDigest, SignOptsArg: expectedOpts}}
	_, err = signer.Sign(nil, expectedDigest, expectedOpts)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "invalid key")

	signer = &bccspCryptoSigner{
		key: expectedKey,
		csp: &mocks.MockBCCSP{SignArgKey: expectedKey, SignDigestArg: expectedDigest, SignOptsArg: expectedOpts}}
	_, err = signer.Sign(nil, nil, expectedOpts)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "invalid digest")

	signer = &bccspCryptoSigner{
		key: expectedKey,
		csp: &mocks.MockBCCSP{SignArgKey: expectedKey, SignDigestArg: expectedDigest, SignOptsArg: expectedOpts}}
	_, err = signer.Sign(nil, expectedDigest, nil)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "invalid opts")
}

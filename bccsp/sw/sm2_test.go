/*
Copyright Hyperledger - Technical Working Group China. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sw

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/bccsp/utils"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm2"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm3"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/x509"
	"github.com/stretchr/testify/require"
	"log"
	"math/big"
	"testing"
)

func TestSignSM2BadParameter(t *testing.T) {
	// Generate a key
	lowLevelPrivateKey,err := sm2.GenerateKey(rand.Reader)
	require.NoError(t,err)

	// Induce an error on the underlying ecdsa algorithm
	msg := []byte("hello world")
	oldN :=lowLevelPrivateKey.Curve.Params().N
	defer func() {lowLevelPrivateKey.Curve.Params().N = oldN}()

	lowLevelPrivateKey.Curve.Params().N = big.NewInt(0)

	_,err =signSM2(lowLevelPrivateKey,msg,nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "zero parameter")  //捕捉错误输出
	lowLevelPrivateKey.Curve.Params().N = oldN

}


func TestVerifySM2(t *testing.T) {
	t.Parallel()

	// Generate a key
	lowLevelPrivateKey, err := sm2.GenerateKey(rand.Reader)
	require.NoError(t,err)

	msg := []byte("hello world")
	sigma, err := signSM2(lowLevelPrivateKey, msg, nil)
	require.NoError(t, err)

	valid, err := verifySM2(&lowLevelPrivateKey.PublicKey, sigma, msg, nil)
	require.NoError(t, err)
	require.True(t, valid)


	R, S, err := utils.UnmarshalSM2Signature(sigma)
	require.NoError(t, err)

	//GetCurveHalfOrdersAtsm2
	S.Add(utils.GetCurveHalfOrdersAtSM2(sm2.P256()), big.NewInt(1))

	sigmaWrongS, err := utils.MarshalSM2Signature(R, S)
    fmt.Println(sigmaWrongS)

	// 暂且不支持脆弱密钥
	//require.NoError(t, err)
	//_, err = verifySM2(&lowLevelPrivateKey.PublicKey, sigmaWrongS, msg, nil)
	//require.Error(t, err)
	//require.Contains(t, err.Error(), "Invalid S. Must be smaller than half the order [")
}

func TestSM2SignerSign(t *testing.T) {

	t.Parallel()


	// Generate a key
	lowLevelPrivateKey, err := sm2.GenerateKey(rand.Reader)
	k := &sm2PrivateKey{lowLevelPrivateKey}
	require.NoError(t, err)
	require.NoError(t, err)

	//Sign
	signer := &sm2Signer{}
	msg := []byte("Hello World")
	sigma, err := signer.Sign(k, msg, nil)

	require.NoError(t, err)
	require.NotNil(t, sigma)


	//Verify
	valid, err := verifySM2(&lowLevelPrivateKey.PublicKey, sigma, msg, nil)
	require.NoError(t, err)
	require.True(t, valid)

	verifierPrivateKey := &sm2PrivateKeyVerifier{}
	valid, err = verifierPrivateKey.Verify(k, sigma, msg, nil)
	require.NoError(t, err)
	require.True(t, valid)

	verifierPublicKey := &sm2PublicKeyKeyVerifier{}
	pk, err := k.PublicKey()
	valid, err = verifierPublicKey.Verify(pk, sigma, msg, nil)
	require.NoError(t, err)
	require.True(t, valid)

}


func TestSM2PrivateKey(t *testing.T) {
	t.Parallel()

	// Generate a key
	lowLevelPrivateKey, err := sm2.GenerateKey(rand.Reader)
	require.NoError(t, err)
	k := &sm2PrivateKey{lowLevelPrivateKey}

	require.False(t, k.Symmetric())
	require.True(t, k.Private())

	_, err = k.Bytes()
	require.Error(t, err)
	require.Contains(t, err.Error(), "Not supported")


	k.privKey = nil
	ski := k.SKI()
	require.Nil(t, ski)

	k.privKey = lowLevelPrivateKey
	ski = k.SKI()
	raw,_:=x509.MarshalPKISM2PrivateKey(k.privKey,nil)
	hash := sm3.New()
	hash.Write(raw)
	ski2 := hash.Sum(nil)
	require.Equal(t, ski2, ski, "SKI is not computed in the right way.")

	pk, err := k.PublicKey()
	require.NoError(t, err)
	require.NotNil(t, pk)
	sm2PK, ok := pk.(*sm2PublicKey)

	require.True(t, ok)
	require.Equal(t, lowLevelPrivateKey.PublicKey, *sm2PK.pubKey)
}

func TestSM2PublicKey(t *testing.T) {
	t.Parallel()

	// Generate a key
	lowLevelPrivateKey, err := sm2.GenerateKey(rand.Reader)
	require.NoError(t, err)
	k := &sm2PublicKey{&lowLevelPrivateKey.PublicKey}

	require.False(t, k.Symmetric())
	require.False(t, k.Private())

	k.pubKey = nil
	ski := k.SKI()
	require.Nil(t, ski)

	k.pubKey = &lowLevelPrivateKey.PublicKey
	ski = k.SKI()
	raw,_ := x509.MarshalPKISM2PublicKey(k.pubKey)
	hash := sm3.New()
	hash.Write(raw)
	ski2 := hash.Sum(nil)
	require.Equal(t, ski, ski2, "SKI is not computed in the right way.")

	pk, err := k.PublicKey()
	require.NoError(t, err)
	require.Equal(t, k, pk)

	bytes, err := k.Bytes()
	require.NoError(t, err)
	bytes2,err := x509.MarshalPKISM2PublicKey(k.pubKey)
	require.Equal(t, bytes2, bytes, "bytes are not computed in the right way.")

	invalidCurve := &elliptic.CurveParams{Name: "P-Invalid"}
	invalidCurve.BitSize = 1024
	k.pubKey = &sm2.PublicKey{Curve: invalidCurve, X: big.NewInt(1), Y: big.NewInt(1)}


	_, err = k.Bytes()
	require.Error(t, err)
	require.Contains(t, err.Error(), "Failed marshalling key [")

}

func TestSm2Sign(t *testing.T) {

	// Generate a key
	lowLevelPrivateKey, err := sm2.GenerateKey(rand.Reader)
	require.NoError(t,err)
	msg := []byte("hello world")
	digest,err :=signSM2(lowLevelPrivateKey,msg,nil)
	log.Println("digest:",digest)

}

func TestSm2Verify(t *testing.T) {

	// Generate a key
	lowLevelPrivateKey, err := sm2.GenerateKey(rand.Reader)
	require.NoError(t,err)

	msg := []byte("hello world")
	digest,err :=signSM2(lowLevelPrivateKey,msg,nil)
	fmt.Println("digest:",digest)

	sk := &sm2PrivateKey{lowLevelPrivateKey}

	//Sign
	signer := &sm2Signer{}
	sigma, err := signer.Sign(sk, msg, nil)

	valid, err :=verifySM2(&(sk.privKey.PublicKey),sigma,msg,nil)
	require.NoError(t, err)
	require.True(t, valid)

}


//Testing默认一次执行四次
func TestSm2GenerateKey(t *testing.T) {
	t.Parallel()

	//Generate a key
	r:=rand.Reader
	fmt.Println(r)
	lowLevelPrivateKey, err := sm2.GenerateKey(r)
	require.NoError(t, err)
	fmt.Println("lowLevelPrivateKey:",lowLevelPrivateKey)

}




type SM2Signature struct {
	R,S *big.Int
}

func TestMarshal(t *testing.T) {
	lowLevelPrivateKey, _ := sm2.GenerateKey(rand.Reader)
	msg := []byte("hello world")
	sigma, _ := signSM2(lowLevelPrivateKey, msg, nil)
	fmt.Println("sigma",sigma)


	sig := new(SM2Signature)
	_, err := asn1.Unmarshal(sigma, sig)
	if err != nil {
		fmt.Println("err")
	}
	sigma2,err := asn1.Marshal(SM2Signature{sig.R,sig.S})
	fmt.Println("sigma2",sigma2)
	require.Equal(t,sigma,sigma2)
}
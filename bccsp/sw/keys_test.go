/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sw

import (

	//"crypto/rand"
	//"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/x509"
	//
	//"encoding/pem"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm2"
	"github.com/stretchr/testify/require"
	"testing"
)



//
//func TestSM2Keys(t *testing.T) {
//	key, err := sm2.GenerateKey(rand.Reader)
//	if err != nil {
//		t.Fatalf("Failed generating sm2 key [%s]", err)
//	}
//
//	// Private Key DER format
//	der, err := privateKeyToDER(key)
//	if err != nil {
//		t.Fatalf("Failed converting private key to DER [%s]", err)
//	}
//	keyFromDER, err := derToPrivateKey(der)
//	if err != nil {
//		t.Fatalf("Failed converting DER to private key [%s]", err)
//	}
//	sm2KeyFromDer := keyFromDER
//	// TODO: check the curve
//	if key.D.Cmp(sm2KeyFromDer.D) != 0 {
//		t.Fatal("Failed converting DER to private key. Invalid D.")
//	}
//	if key.X.Cmp(sm2KeyFromDer.X) != 0 {
//		t.Fatal("Failed converting DER to private key. Invalid X coordinate.")
//	}
//	if key.Y.Cmp(sm2KeyFromDer.Y) != 0 {
//		t.Fatal("Failed converting DER to private key. Invalid Y coordinate.")
//	}
//
//	// Private Key PEM format
//	rawPEM, err := privateKeyToPEM(key, nil)
//	if err != nil {
//		t.Fatalf("Failed converting private key to PEM [%s]", err)
//	}
//	pemBlock, _ := pem.Decode(rawPEM)
//	if pemBlock.Type != "PRIVATE KEY" {
//		t.Fatalf("Expected type 'PRIVATE KEY' but found '%s'", pemBlock.Type)
//	}
//	_, err = x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
//	if err != nil {
//		t.Fatalf("Failed to parse PKCS#8 private key [%s]", err)
//	}
//	keyFromPEM, err := pemToPrivateKey(rawPEM, nil)
//	if err != nil {
//		t.Fatalf("Failed converting DER to private key [%s]", err)
//	}
//	sm2KeyFromPEM := keyFromPEM
//	// TODO: check the curve
//	if key.D.Cmp(sm2KeyFromPEM.D) != 0 {
//		t.Fatal("Failed converting PEM to private key. Invalid D.")
//	}
//	if key.X.Cmp(sm2KeyFromPEM.X) != 0 {
//		t.Fatal("Failed converting PEM to private key. Invalid X coordinate.")
//	}
//	if key.Y.Cmp(sm2KeyFromPEM.Y) != 0 {
//		t.Fatal("Failed converting PEM to private key. Invalid Y coordinate.")
//	}
//
//	// Nil Private Key <-> PEM
//	_, err = privateKeyToPEM(nil, nil)
//	if err == nil {
//		t.Fatal("publicKeyToPEM should fail on nil")
//	}
//
//	_, err = privateKeyToPEM((*sm2.PrivateKey)(nil), nil)
//	if err == nil {
//		t.Fatal("PrivateKeyToPEM should fail on nil")
//	}
//
//
//
//	_, err = pemToPrivateKey(nil, nil)
//	if err == nil {
//		t.Fatal("pemToPublicKey should fail on nil")
//	}
//
//	_, err = pemToPrivateKey([]byte{0, 1, 3, 4}, nil)
//	if err == nil {
//		t.Fatal("pemToPublicKey should fail invalid PEM")
//	}
//
//	_, err = pemToPrivateKey(nil,nil)
//	if err == nil {
//		t.Fatal("DERToPrivateKey should fail on nil")
//	}
//
//	_, err = derToPrivateKey([]byte{0, 1, 3, 4})
//	if err == nil {
//		t.Fatal("DERToPrivateKey should fail on invalid DER")
//	}
//
//	_, err = privateKeyToDER(nil)
//	if err == nil {
//		t.Fatal("DERToPrivateKey should fail on nil")
//	}
//
//	// Private Key Encrypted PEM format
//	encPEM, err := privateKeyToPEM(key, []byte("passwd"))
//	if err != nil {
//		t.Fatalf("Failed converting private key to encrypted PEM [%s]", err)
//	}
//	_, err = pemToPrivateKey(encPEM, nil)
//	require.Error(t, err)
//	encKeyFromPEM, err := pemToPrivateKey(encPEM, []byte("passwd"))
//	if err != nil {
//		t.Fatalf("Failed converting DER to private key [%s]", err)
//	}
//	sm2KeyFromEncPEM := encKeyFromPEM
//	// TODO: check the curve
//	if key.D.Cmp(sm2KeyFromEncPEM.D) != 0 {
//		t.Fatal("Failed converting encrypted PEM to private key. Invalid D.")
//	}
//	if key.X.Cmp(sm2KeyFromEncPEM.X) != 0 {
//		t.Fatal("Failed converting encrypted PEM to private key. Invalid X coordinate.")
//	}
//	if key.Y.Cmp(sm2KeyFromEncPEM.Y) != 0 {
//		t.Fatal("Failed converting encrypted PEM to private key. Invalid Y coordinate.")
//	}
//
//	// Public Key PEM format
//	rawPEM, err = publicKeyToPEM(&key.PublicKey, nil)
//	if err != nil {
//		t.Fatalf("Failed converting public key to PEM [%s]", err)
//	}
//	pemBlock, _ = pem.Decode(rawPEM)
//	if pemBlock.Type != "PUBLIC KEY" {
//		t.Fatalf("Expected type 'PUBLIC KEY' but found '%s'", pemBlock.Type)
//	}
//	keyFromPEM, err = pemToPublicKey(rawPEM, nil)
//	if err != nil {
//		t.Fatalf("Failed converting DER to public key [%s]", err)
//	}
//	sm2PkFromPEM := keyFromPEM
//	// TODO: check the curve
//	if key.X.Cmp(sm2PkFromPEM.X) != 0 {
//		t.Fatal("Failed converting PEM to private key. Invalid X coordinate.")
//	}
//	if key.Y.Cmp(sm2PkFromPEM.Y) != 0 {
//		t.Fatal("Failed converting PEM to private key. Invalid Y coordinate.")
//	}
//
//	// Nil Public Key <-> PEM
//	_, err = publicKeyToPEM(nil, nil)
//	if err == nil {
//		t.Fatal("publicKeyToPEM should fail on nil")
//	}
//
//	_, err = pemToPublicKey(nil, nil)
//	if err == nil {
//		t.Fatal("pemToPublicKey should fail on nil")
//	}
//
//	_, err = pemToPublicKey([]byte{0, 1, 3, 4}, nil)
//	if err == nil {
//		t.Fatal("pemToPublicKey should fail on invalid PEM")
//	}
//
//	// Public Key Encrypted PEM format
//	encPEM, err = publicKeyToPEM(&key.PublicKey, []byte("passwd"))
//	if err != nil {
//		t.Fatalf("Failed converting private key to encrypted PEM [%s]", err)
//	}
//	_, err = pemToPublicKey(encPEM, nil)
//	require.Error(t, err)
//	pkFromEncPEM, err := pemToPublicKey(encPEM, []byte("passwd"))
//	if err != nil {
//		t.Fatalf("Failed converting DER to private key [%s]", err)
//	}
//	sm2PkFromEncPEM := pkFromEncPEM
//	// TODO: check the curve
//	if key.X.Cmp(sm2PkFromEncPEM.X) != 0 {
//		t.Fatal("Failed converting encrypted PEM to private key. Invalid X coordinate.")
//	}
//	if key.Y.Cmp(sm2PkFromEncPEM.Y) != 0 {
//		t.Fatal("Failed converting encrypted PEM to private key. Invalid Y coordinate.")
//	}
//
//	_, err = pemToPublicKey(encPEM, []byte("passw"))
//	if err == nil {
//		t.Fatal("pemToPublicKey should fail on wrong password")
//	}
//
//	_, err = pemToPublicKey(encPEM, []byte("passw"))
//	if err == nil {
//		t.Fatal("pemToPublicKey should fail on nil password")
//	}
//
//	_, err = pemToPublicKey(nil, []byte("passwd"))
//	if err == nil {
//		t.Fatal("pemToPublicKey should fail on nil PEM")
//	}
//
//	_, err = pemToPublicKey([]byte{0, 1, 3, 4}, []byte("passwd"))
//	if err == nil {
//		t.Fatal("pemToPublicKey should fail on invalid PEM")
//	}
//
//	_, err = pemToPublicKey(nil, []byte("passw"))
//	if err == nil {
//		t.Fatal("pemToPublicKey should fail on nil PEM and wrong password")
//	}
//
//	// Public Key DER format
//	der, err = publicKeyToDER(&key.PublicKey)
//	require.NoError(t, err)
//	keyFromDER, err = derToPublicKey(der)
//	require.NoError(t, err)
//	sm2PkFromPEM = keyFromDER
//	// TODO: check the curve
//	if key.X.Cmp(sm2PkFromPEM.X) != 0 {
//		t.Fatal("Failed converting PEM to private key. Invalid X coordinate.")
//	}
//	if key.Y.Cmp(sm2PkFromPEM.Y) != 0 {
//		t.Fatal("Failed converting PEM to private key. Invalid Y coordinate.")
//	}
//}

func TestSM4Key(t *testing.T) {
	k := []byte{0, 1, 2, 3, 4, 5}
	pem := sm4ToPEM(k)

	k2, err := pemToSM4(pem, nil)
	require.NoError(t, err)
	require.Equal(t, k, k2)

	pem, err = sm4ToEncryptedPEM(k, k)
	require.NoError(t, err)

	k2, err = pemToSM4(pem, k)
	require.NoError(t, err)
	require.Equal(t, k, k2)

	_, err = pemToSM4(pem, nil)
	require.Error(t, err)

	_, err = sm4ToEncryptedPEM(k, nil)
	require.NoError(t, err)

	k2, err = pemToSM4(pem, k)
	require.NoError(t, err)
	require.Equal(t, k, k2)
}

func TestDERToPublicKey(t *testing.T) {
	_, err := derToPublicKey(nil)
	require.Error(t, err)
}

func TestNil(t *testing.T) {
	_, err := privateKeyToEncryptedPEM(nil, nil)
	require.Error(t, err)

	_, err = privateKeyToEncryptedPEM((*sm2.PrivateKey)(nil), nil)
	require.Error(t, err)
	
	_, err = pemToSM4(nil, nil)
	require.Error(t, err)

	_, err = sm4ToEncryptedPEM(nil, nil)
	require.Error(t, err)

	_, err = publicKeyToPEM(nil, nil)
	require.Error(t, err)
	_, err = publicKeyToPEM((*sm2.PublicKey)(nil), nil)
	require.Error(t, err)

	_, err = publicKeyToPEM(nil, []byte("hello world"))
	require.Error(t, err)
	

	_, err = publicKeyToDER(nil)
	require.Error(t, err)
	_, err = publicKeyToDER((*sm2.PublicKey)(nil))
	require.Error(t, err)

	_, err = publicKeyToEncryptedPEM(nil, nil)
	require.Error(t, err)
	_, err = publicKeyToEncryptedPEM((*sm2.PublicKey)(nil), nil)
	require.Error(t, err)

}

/*
Copyright Hyperledger - Technical Working Group China. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sw

import (
	"bytes"
	"crypto/rand"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/bccsp/mocks"

	gmbccsp "github.com/Hyperledger-TWGC/fabric-gm-plugins/bccsp"

	"fmt"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm4"
	"github.com/stretchr/testify/require"
	"io"
	"math/big"
	mrand "math/rand"
	"testing"
)

func TestNewSM4(t *testing.T){
	fmt.Println(sm4.BlockSize)
	var key =[]byte("1234567890abcdef")
	a,err:=sm4.NewCipher(key)
	if err != nil{
		fmt.Println("error")
	}
	fmt.Println(a)

}


// TestCBCPKCS7EncryptCBCPKCS7Decrypt encrypts using CBCPKCS7Encrypt and decrypts using CBCPKCS7Decrypt.
func TestCBCPKCS7EncryptCBCPKCS7Decrypt(t *testing.T) {
	t.Parallel()

	// Note: The purpose of this test is not to test SM4-256 in CBC mode's strength
	// ... but rather to verify the code wrapping/unwrapping the cipher.
	key := make([]byte, sm4.BlockSize)
	rand.Reader.Read(key)

	//                  123456789012345678901234567890123456789012
	var ptext = []byte("a message with arbitrary length (42 bytes)")

	encrypted, encErr := SM4CBCPKCS7Encrypt(key, ptext)
	if encErr != nil {
		t.Fatalf("Error encrypting '%s': %s", ptext, encErr)
	}

	decrypted, dErr := SM4CBCPKCS7Decrypt(key, encrypted)
	if dErr != nil {
		t.Fatalf("Error decrypting the encrypted '%s': %v", ptext, dErr)
	}

	if string(ptext[:]) != string(decrypted[:]) {
		t.Fatal("Decrypt( Encrypt( ptext ) ) != ptext: Ciphertext decryption with the same key must result in the original plaintext!")
	}
}

// TestPKCS7Padding verifies the PKCS#7 padding, using a human readable plaintext.
func TestPKCS7Padding(t *testing.T) {
	t.Parallel()

	// 0 byte/length ptext
	ptext := []byte("")
	expected := []byte{16, 16, 16, 16,
		16, 16, 16, 16,
		16, 16, 16, 16,
		16, 16, 16, 16}
	result := pkcs7Padding(ptext)

	if !bytes.Equal(expected, result) {
		t.Fatal("Padding error! Expected: ", expected, "', received: '", result, "'")
	}

	// 1 byte/length ptext
	ptext = []byte("1")
	expected = []byte{'1', 15, 15, 15,
		15, 15, 15, 15,
		15, 15, 15, 15,
		15, 15, 15, 15}
	result = pkcs7Padding(ptext)

	if !bytes.Equal(expected, result) {
		t.Fatal("Padding error! Expected: '", expected, "', received: '", result, "'")
	}

	// 2 byte/length ptext
	ptext = []byte("12")
	expected = []byte{'1', '2', 14, 14,
		14, 14, 14, 14,
		14, 14, 14, 14,
		14, 14, 14, 14}
	result = pkcs7Padding(ptext)

	if !bytes.Equal(expected, result) {
		t.Fatal("Padding error! Expected: '", expected, "', received: '", result, "'")
	}

	// 3 to sm4.BlockSize-1 byte plaintext
	ptext = []byte("1234567890ABCDEF")
	for i := 3; i < sm4.BlockSize; i++ {
		result := pkcs7Padding(ptext[:i])

		padding := sm4.BlockSize - i
		expectedPadding := bytes.Repeat([]byte{byte(padding)}, padding)
		expected = append(ptext[:i], expectedPadding...)

		if !bytes.Equal(result, expected) {
			t.Fatal("Padding error! Expected: '", expected, "', received: '", result, "'")
		}
	}

	// sm4.BlockSize length ptext
	ptext = bytes.Repeat([]byte{byte('x')}, sm4.BlockSize)
	result = pkcs7Padding(ptext)

	expectedPadding := bytes.Repeat([]byte{byte(sm4.BlockSize)}, sm4.BlockSize)
	expected = append(ptext, expectedPadding...)

	if len(result) != 2*sm4.BlockSize {
		t.Fatal("Padding error: expected the length of the returned slice to be 2 times sm4.BlockSize")
	}

	if !bytes.Equal(expected, result) {
		t.Fatal("Padding error! Expected: '", expected, "', received: '", result, "'")
	}
}

// TestPKCS7UnPadding verifies the PKCS#7 unpadding, using a human readable plaintext.
func TestPKCS7UnPadding(t *testing.T) {
	t.Parallel()

	// 0 byte/length ptext
	expected := []byte("")
	ptext := []byte{16, 16, 16, 16,
		16, 16, 16, 16,
		16, 16, 16, 16,
		16, 16, 16, 16}

	result, _ := pkcs7UnPadding(ptext)

	if !bytes.Equal(expected, result) {
		t.Fatal("UnPadding error! Expected: '", expected, "', received: '", result, "'")
	}

	// 1 byte/length ptext
	expected = []byte("1")
	ptext = []byte{'1', 15, 15, 15,
		15, 15, 15, 15,
		15, 15, 15, 15,
		15, 15, 15, 15}

	result, _ = pkcs7UnPadding(ptext)

	if !bytes.Equal(expected, result) {
		t.Fatal("UnPadding error! Expected: '", expected, "', received: '", result, "'")
	}

	// 2 byte/length ptext
	expected = []byte("12")
	ptext = []byte{'1', '2', 14, 14,
		14, 14, 14, 14,
		14, 14, 14, 14,
		14, 14, 14, 14}

	result, _ = pkcs7UnPadding(ptext)

	if !bytes.Equal(expected, result) {
		t.Fatal("UnPadding error! Expected: '", expected, "', received: '", result, "'")
	}

	// 3 to sm4.BlockSize-1 byte plaintext
	base := []byte("1234567890ABCDEF")
	for i := 3; i < sm4.BlockSize; i++ {
		iPad := sm4.BlockSize - i
		padding := bytes.Repeat([]byte{byte(iPad)}, iPad)
		ptext = append(base[:i], padding...)

		expected := base[:i]
		result, _ := pkcs7UnPadding(ptext)

		if !bytes.Equal(result, expected) {
			t.Fatal("UnPadding error! Expected: '", expected, "', received: '", result, "'")
		}
	}

	// sm4.BlockSize length ptext
	expected = bytes.Repeat([]byte{byte('x')}, sm4.BlockSize)
	padding := bytes.Repeat([]byte{byte(sm4.BlockSize)}, sm4.BlockSize)
	ptext = append(expected, padding...)

	result, _ = pkcs7UnPadding(ptext)

	if !bytes.Equal(expected, result) {
		t.Fatal("UnPadding error! Expected: '", expected, "', received: '", result, "'")
	}
}

// TestCBCEncryptCBCPKCS7Decrypt_BlockSizeLengthPlaintext verifies that CBCPKCS7Decrypt returns an error
// when attempting to decrypt ciphertext of an irreproducible length.
func TestCBCEncryptCBCPKCS7Decrypt_BlockSizeLengthPlaintext(t *testing.T) {
	t.Parallel()

	// One of the purposes of this test is to also document and clarify the expected behavior, i.e., that an extra
	// block is appended to the message at the padding stage, as per the spec of PKCS#7 v1.5 [see RFC-2315 p.21]
	key := make([]byte, 16)
	rand.Reader.Read(key)

	//                  1234567890123456
	var ptext = []byte("a 16 byte messag")

	encrypted, encErr := sm4CBCEncrypt(key, ptext)
	if encErr != nil {
		t.Fatalf("Error encrypting '%s': %v", ptext, encErr)
	}

	decrypted, dErr := SM4CBCPKCS7Decrypt(key, encrypted)
	if dErr == nil {
		t.Fatalf("Expected an error decrypting ptext '%s'. Decrypted to '%v'", dErr, decrypted)
	}
}

// TestCBCPKCS7EncryptCBCDecrypt_ExpectingCorruptMessage verifies that CBCDecrypt can decrypt the unpadded
// version of the ciphertext, of a message of BlockSize length.
func TestCBCPKCS7EncryptCBCDecrypt_ExpectingCorruptMessage(t *testing.T) {
	t.Parallel()

	// One of the purposes of this test is to also document and clarify the expected behavior, i.e., that an extra
	// block is appended to the message at the padding stage, as per the spec of PKCS#7 v1.5 [see RFC-2315 p.21]
	key := make([]byte, 16)
	rand.Reader.Read(key)

	//                  0123456789ABCDEF
	var ptext = []byte("a 16 byte messag")

	encrypted, encErr := SM4CBCPKCS7Encrypt(key, ptext)
	if encErr != nil {
		t.Fatalf("Error encrypting ptext %v", encErr)
	}

	decrypted, dErr := sm4CBCDecrypt(key, encrypted)
	if dErr != nil {
		t.Fatalf("Error encrypting ptext %v, %v", dErr, decrypted)
	}

	if string(ptext[:]) != string(decrypted[:sm4.BlockSize]) {
		t.Log("ptext: ", ptext)
		t.Log("decrypted: ", decrypted[:sm4.BlockSize])
		t.Fatal("Encryption->Decryption with same key should result in original ptext")
	}

	if !bytes.Equal(decrypted[sm4.BlockSize:], bytes.Repeat([]byte{byte(sm4.BlockSize)}, sm4.BlockSize)) {
		t.Fatal("Expected extra block with padding in encrypted ptext", decrypted)
	}
}

// TestCBCPKCS7Encrypt_EmptyPlaintext encrypts and pad an empty ptext. Verifying as well that the ciphertext length is as expected.
func TestCBCPKCS7Encrypt_EmptyPlaintext(t *testing.T) {
	t.Parallel()

	key := make([]byte, 16)
	rand.Reader.Read(key)

	t.Log("Generated key: ", key)

	var emptyPlaintext = []byte("")
	t.Log("Plaintext length: ", len(emptyPlaintext))

	ciphertext, encErr := SM4CBCPKCS7Encrypt(key, emptyPlaintext)
	if encErr != nil {
		t.Fatalf("Error encrypting '%v'", encErr)
	}

	// Expected ciphertext length: 16 (=16)
	// As part of the padding, at least one block gets encrypted (while the first block is the IV)
	const expectedLength = sm4.BlockSize + sm4.BlockSize
	if len(ciphertext) != expectedLength {
		t.Fatalf("Wrong ciphertext length. Expected %d, received %d", expectedLength, len(ciphertext))
	}

	t.Log("Ciphertext length: ", len(ciphertext))
	t.Log("Cipher: ", ciphertext)
}

// TestCBCEncrypt_EmptyPlaintext encrypts an empty message. Verifying as well that the ciphertext length is as expected.
func TestCBCEncrypt_EmptyPlaintext(t *testing.T) {
	t.Parallel()

	key := make([]byte, 16)
	rand.Reader.Read(key)
	t.Log("Generated key: ", key)

	var emptyPlaintext = []byte("")
	t.Log("Message length: ", len(emptyPlaintext))

	ciphertext, encErr := sm4CBCEncrypt(key, emptyPlaintext)
	require.NoError(t, encErr)

	t.Log("Ciphertext length: ", len(ciphertext))

	// Expected cipher length: sm4.BlockSize, the first and only block is the IV
	var expectedLength = sm4.BlockSize

	if len(ciphertext) != expectedLength {
		t.Fatalf("Wrong ciphertext length. Expected: '%d', received: '%d'", expectedLength, len(ciphertext))
	}
	t.Log("Ciphertext: ", ciphertext)
}

// TestCBCPKCS7Encrypt_VerifyRandomIVs encrypts twice with same key. The first 16 bytes should be different if IV is generated randomly.
func TestCBCPKCS7Encrypt_VerifyRandomIVs(t *testing.T) {
	t.Parallel()

	key := make([]byte, sm4.BlockSize)
	rand.Reader.Read(key)
	t.Log("Key 1", key)

	var ptext = []byte("a message to encrypt")

	ciphertext1, err := SM4CBCPKCS7Encrypt(key, ptext)
	if err != nil {
		t.Fatalf("Error encrypting '%s': %s", ptext, err)
	}

	// Expecting a different IV if same message is encrypted with same key
	ciphertext2, err := SM4CBCPKCS7Encrypt(key, ptext)
	if err != nil {
		t.Fatalf("Error encrypting '%s': %s", ptext, err)
	}

	iv1 := ciphertext1[:sm4.BlockSize]
	iv2 := ciphertext2[:sm4.BlockSize]

	t.Log("Ciphertext1: ", iv1)
	t.Log("Ciphertext2: ", iv2)
	t.Log("bytes.Equal: ", bytes.Equal(iv1, iv2))

	if bytes.Equal(iv1, iv2) {
		t.Fatal("Error: ciphertexts contain identical initialization vectors (IVs)")
	}
}

// TestCBCPKCS7Encrypt_CorrectCiphertextLengthCheck verifies that the returned ciphertext lengths are as expected.
func TestCBCPKCS7Encrypt_CorrectCiphertextLengthCheck(t *testing.T) {
	t.Parallel()

	key := make([]byte, sm4.BlockSize)
	rand.Reader.Read(key)

	// length of message (in bytes) == sm4.BlockSize (16 bytes)
	// The expected cipher length = IV length (1 block) + 1 block message

	var ptext = []byte("0123456789ABCDEF")

	for i := 1; i < sm4.BlockSize; i++ {
		ciphertext, err := SM4CBCPKCS7Encrypt(key, ptext[:i])
		if err != nil {
			t.Fatal("Error encrypting '", ptext, "'")
		}

		expectedLength := sm4.BlockSize + sm4.BlockSize
		if len(ciphertext) != expectedLength {
			t.Fatalf("Incorrect ciphertext incorrect: expected '%d', received '%d'", expectedLength, len(ciphertext))
		}
	}
}

// TestCBCEncryptCBCDecrypt_KeyMismatch attempts to decrypt with a different key than the one used for encryption.
func TestCBCEncryptCBCDecrypt_KeyMismatch(t *testing.T) {
	t.Parallel()

	// Generate a random key
	key := make([]byte, sm4.BlockSize)
	rand.Reader.Read(key)

	// Clone & tamper with the key
	wrongKey := make([]byte, sm4.BlockSize)
	copy(wrongKey, key[:])
	wrongKey[0] = key[0] + 1

	var ptext = []byte("1234567890ABCDEF")
	encrypted, encErr := sm4CBCEncrypt(key, ptext)
	if encErr != nil {
		t.Fatalf("Error encrypting '%s': %v", ptext, encErr)
	}

	decrypted, decErr := sm4CBCDecrypt(wrongKey, encrypted)
	if decErr != nil {
		t.Fatalf("Error decrypting '%s': %v", ptext, decErr)
	}

	if string(ptext[:]) == string(decrypted[:]) {
		t.Fatal("Decrypting a ciphertext with a different key than the one used for encrypting it - should not result in the original plaintext.")
	}
}

// TestCBCEncryptCBCDecrypt encrypts with CBCEncrypt and decrypt with CBCDecrypt.
func TestCBCEncryptCBCDecrypt(t *testing.T) {
	t.Parallel()

	key := make([]byte, 16)
	rand.Reader.Read(key)

	//                  1234567890123456
	var ptext = []byte("a 16 byte messag")

	encrypted, encErr := sm4CBCEncrypt(key, ptext)
	if encErr != nil {
		t.Fatalf("Error encrypting '%s': %v", ptext, encErr)
	}

	decrypted, decErr := sm4CBCDecrypt(key, encrypted)
	if decErr != nil {
		t.Fatalf("Error decrypting '%s': %v", ptext, decErr)
	}

	if string(ptext[:]) != string(decrypted[:]) {
		t.Fatal("Encryption->Decryption with same key should result in the original plaintext.")
	}
}

// TestCBCEncryptWithRandCBCDecrypt encrypts with CBCEncrypt using the passed prng and decrypt with CBCDecrypt.
func TestCBCEncryptWithRandCBCDecrypt(t *testing.T) {
	t.Parallel()

	key := make([]byte, 16)
	rand.Reader.Read(key)

	//                  1234567890123456
	var ptext = []byte("a 16 byte messag")

	encrypted, encErr := sm4CBCEncryptWithRand(rand.Reader, key, ptext)
	if encErr != nil {
		t.Fatalf("Error encrypting '%s': %v", ptext, encErr)
	}

	decrypted, decErr := sm4CBCDecrypt(key, encrypted)
	if decErr != nil {
		t.Fatalf("Error decrypting '%s': %v", ptext, decErr)
	}

	if string(ptext[:]) != string(decrypted[:]) {
		t.Fatal("Encryption->Decryption with same key should result in the original plaintext.")
	}
}

// TestCBCEncryptWithIVCBCDecrypt encrypts with CBCEncrypt using the passed IV and decrypt with CBCDecrypt.
func TestCBCEncryptWithIVCBCDecrypt(t *testing.T) {
	t.Parallel()

	key := make([]byte, 16)
	rand.Reader.Read(key)

	//                  1234567890123456
	var ptext = []byte("a 16 byte messag")

	iv := make([]byte, sm4.BlockSize)
	_, err := io.ReadFull(rand.Reader, iv)
	require.NoError(t, err)

	encrypted, encErr := sm4CBCEncryptWithIV(iv, key, ptext)
	if encErr != nil {
		t.Fatalf("Error encrypting '%s': %v", ptext, encErr)
	}

	decrypted, decErr := sm4CBCDecrypt(key, encrypted)
	if decErr != nil {
		t.Fatalf("Error decrypting '%s': %v", ptext, decErr)
	}

	if string(ptext[:]) != string(decrypted[:]) {
		t.Fatal("Encryption->Decryption with same key should result in the original plaintext.")
	}
}

// TestSM4RelatedUtilFunctions tests various functions commonly used in fabric wrt SM4
func TestSM4RelatedUtilFunctions(t *testing.T) {
	t.Parallel()

	key, err := GetRandomBytes(16)
	if err != nil {
		t.Fatalf("Failed generating SM4 key [%s]", err)
	}

	for i := 1; i < 100; i++ {
		l, err := rand.Int(rand.Reader, big.NewInt(1024))
		if err != nil {
			t.Fatalf("Failed generating SM4 key [%s]", err)
		}
		msg, err := GetRandomBytes(int(l.Int64()) + 1)
		if err != nil {
			t.Fatalf("Failed generating SM4 key [%s]", err)
		}

		ct, err := SM4CBCPKCS7Encrypt(key, msg)
		if err != nil {
			t.Fatalf("Failed encrypting [%s]", err)
		}

		msg2, err := SM4CBCPKCS7Decrypt(key, ct)
		if err != nil {
			t.Fatalf("Failed decrypting [%s]", err)
		}

		if !bytes.Equal(msg, msg2) {
			t.Fatalf("Wrong decryption output [%x][%x]", msg, msg2)
		}
	}
}

// TestVariousSM4KeyEncoding tests some SM4 <-> PEM conversions
func TestVariousSM4KeyEncoding(t *testing.T) {
	t.Parallel()

	key, err := GetRandomBytes(16)
	if err != nil {
		t.Fatalf("Failed generating SM4 key [%s]", err)
	}

	// PEM format
	pem := sm4ToPEM(key)

	keyFromPEM, err := pemToSM4(pem, nil)

	if err != nil {
		t.Fatalf("Failed converting PEM to SM4 key [%s]", err)
	}
	if !bytes.Equal(key, keyFromPEM) {
		t.Fatalf("Failed converting PEM to SM4 key. Keys are different [%x][%x]", key, keyFromPEM)
	}

	// Encrypted PEM format
	pem, err = sm4ToEncryptedPEM(key, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting SM4 key to Encrypted PEM [%s]", err)
	}
	keyFromPEM, err = pemToSM4(pem, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting encrypted PEM to SM4 key [%s]", err)
	}
	if !bytes.Equal(key, keyFromPEM) {
		t.Fatalf("Failed converting encrypted PEM to SM4 key. Keys are different [%x][%x]", key, keyFromPEM)
	}
}

func TestPkcs7UnPaddingInvalidInputs(t *testing.T) {
	t.Parallel()

	_, err := pkcs7UnPadding([]byte{1, 2, 3, 4, 5, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	require.Error(t, err)
	require.Equal(t, "Invalid pkcs7 padding (pad[i] != unpadding)", err.Error())
}

func TestSM4CBCEncryptInvalidInputs(t *testing.T) {
	t.Parallel()

	_, err := sm4CBCEncrypt(nil, []byte{0, 1, 2, 3})
	require.Error(t, err)
	require.Equal(t, "Invalid plaintext. It must be a multiple of the block size", err.Error())

	_, err = sm4CBCEncrypt([]byte{0}, []byte{1, 2, 3, 4, 5, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	require.Error(t, err)
}

func TestSM4CBCDecryptInvalidInputs(t *testing.T) {
	t.Parallel()

	_, err := sm4CBCDecrypt([]byte{0}, []byte{1, 2, 3, 4, 5, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	require.Error(t, err)

	_, err = sm4CBCDecrypt([]byte{1, 2, 3, 4, 5, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte{0})
	require.Error(t, err)

	_, err = sm4CBCDecrypt([]byte{1, 2, 3, 4, 5, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		[]byte{1, 2, 3, 4, 5, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	require.Error(t, err)
}

// TestSM4CBCPKCS7EncryptorDecrypt tests the integration of
// sm4cbcpkcs7Encryptor and sm4cbcpkcs7Decryptor
func TestSM4CBCPKCS7EncryptorDecrypt(t *testing.T) {
	t.Parallel()

	raw, err := GetRandomBytes(16)
	require.NoError(t, err)

	k := &sm4PrivateKey{privKey: raw, exportable: false}

	msg := []byte("Hello World")
	encryptor := &sm4cbcpkcs7Encryptor{}

	_, err = encryptor.Encrypt(k, msg, nil)
	require.Error(t, err)

	_, err = encryptor.Encrypt(k, msg, &mocks.EncrypterOpts{})
	require.Error(t, err)

	_, err = encryptor.Encrypt(k, msg, &gmbccsp.SM4CBCPKCS7ModeOpts{IV: []byte{1}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid IV. It must have length the block size")

	_, err = encryptor.Encrypt(k, msg, &gmbccsp.SM4CBCPKCS7ModeOpts{IV: []byte{1}, PRNG: rand.Reader})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid options. Either IV or PRNG should be different from nil, or both nil.")

	_, err = encryptor.Encrypt(k, msg, gmbccsp.SM4CBCPKCS7ModeOpts{})
	require.NoError(t, err)

	ct, err := encryptor.Encrypt(k, msg, &gmbccsp.SM4CBCPKCS7ModeOpts{})
	require.NoError(t, err)

	decryptor := &sm4cbcpkcs7Decryptor{}

	_, err = decryptor.Decrypt(k, ct, nil)
	require.Error(t, err)

	_, err = decryptor.Decrypt(k, ct, &mocks.EncrypterOpts{})
	require.Error(t, err)

	msg2, err := decryptor.Decrypt(k, ct, &gmbccsp.SM4CBCPKCS7ModeOpts{})
	require.NoError(t, err)
	require.Equal(t, msg, msg2)
}

func TestSM4CBCPKCS7EncryptorWithIVSameCiphertext(t *testing.T) {
	t.Parallel()

	raw, err := GetRandomBytes(16)
	require.NoError(t, err)

	k := &sm4PrivateKey{privKey: raw, exportable: false}

	msg := []byte("Hello World")
	encryptor := &sm4cbcpkcs7Encryptor{}

	iv := make([]byte, sm4.BlockSize)

	ct, err := encryptor.Encrypt(k, msg, &gmbccsp.SM4CBCPKCS7ModeOpts{IV: iv})
	require.NoError(t, err)
	require.NotNil(t, ct)
	require.Equal(t, iv, ct[:sm4.BlockSize])

	ct2, err := encryptor.Encrypt(k, msg, &gmbccsp.SM4CBCPKCS7ModeOpts{IV: iv})
	require.NoError(t, err)
	require.NotNil(t, ct2)
	require.Equal(t, iv, ct2[:sm4.BlockSize])

	require.Equal(t, ct, ct2)
}

func TestSM4CBCPKCS7EncryptorWithRandSameCiphertext(t *testing.T) {
	t.Parallel()

	raw, err := GetRandomBytes(16)
	require.NoError(t, err)

	k := &sm4PrivateKey{privKey: raw, exportable: false}

	msg := []byte("Hello World")
	encryptor := &sm4cbcpkcs7Encryptor{}

	r := mrand.New(mrand.NewSource(0))
	iv := make([]byte, sm4.BlockSize)
	_, err = io.ReadFull(r, iv)
	require.NoError(t, err)

	r = mrand.New(mrand.NewSource(0))
	ct, err := encryptor.Encrypt(k, msg, &gmbccsp.SM4CBCPKCS7ModeOpts{PRNG: r})
	require.NoError(t, err)
	require.NotNil(t, ct)
	require.Equal(t, iv, ct[:sm4.BlockSize])

	r = mrand.New(mrand.NewSource(0))
	ct2, err := encryptor.Encrypt(k, msg, &gmbccsp.SM4CBCPKCS7ModeOpts{PRNG: r})
	require.NoError(t, err)
	require.NotNil(t, ct2)
	require.Equal(t, iv, ct2[:sm4.BlockSize])

	require.Equal(t, ct, ct2)
}

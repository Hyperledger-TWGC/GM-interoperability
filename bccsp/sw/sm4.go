package sw

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/bccsp"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm4"
	"io"
)

func GetRandomBytes(len int) ([]byte, error) {
	if len < 0 {
		return nil, errors.New("Len must be larger than 0")
	}

	buffer := make([]byte, len)

	n, err := rand.Read(buffer)
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, fmt.Errorf("Buffer not filled. Requested [%d], got [%d]", len, n)
	}

	return buffer, nil
}


func pkcs7Padding(src []byte) []byte {

	padding :=  - len(src)%sm4.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

//blockSize 密钥长度大小 --->  如 sm4.blockSize
func pkcs7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])


	if unpadding > sm4.BlockSize || unpadding == 0 {
		return nil, errors.New("Invalid pkcs7 padding (unpadding > sm4.BlockSize || unpadding == 0)")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("Invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}

func sm4CBCEncrypt(key,s []byte) ([]byte,error) {
	return sm4CBCEncryptWithRand(rand.Reader,key,s)
}

func sm4CBCEncryptWithRand(prng io.Reader,key,s []byte) ([]byte,error) {
	if len(s)%sm4.BlockSize != 0 {
		return nil,errors.New("Invalid plaintext. It must be a multiple of the block size")
	}
	block,err := sm4.NewCipher(key)
	if err != nil {
		return nil ,err
	}

	ciphertext := make([]byte,sm4.BlockSize +len(s))
	iv := ciphertext[:sm4.BlockSize ]
	if _,err := io.ReadFull(prng,iv);err != nil {
		return nil,err
	}
	mode := cipher.NewCBCEncrypter(block,iv)
	mode.CryptBlocks(ciphertext[sm4.BlockSize :],s)
	return ciphertext,nil
}

func sm4CBCEncryptWithIV(IV []byte,key,s []byte) ([]byte,error) {
	if len(s)%sm4.BlockSize != 0 {
		return nil,errors.New("Invalid plaintext. It must be a multiple of the block size")
	}
	if len(IV) != sm4.BlockSize {
		return nil,errors.New("Invalid IV. It must have length the block size")
	}

	block,err := sm4.NewCipher(key)
	if err != nil {
		return nil,err
	}
	ciphertext := make([]byte,sm4.BlockSize+len(s))
	copy(ciphertext[:sm4.BlockSize],IV)
	mode := cipher.NewCBCEncrypter(block,IV)
	mode.CryptBlocks(ciphertext[sm4.BlockSize:],s)
	return ciphertext,nil
}


func sm4CBCDecrypt(key,src []byte) ([]byte,error) {
	block,err := sm4.NewCipher(key)
	if err != nil {
		return nil,err
	}

	if len(src) < sm4.BlockSize {
		return nil,errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}

	iv := src[:sm4.BlockSize]
	src = src[sm4.BlockSize:]

	if len(src)%sm4.BlockSize != 0 {
		return nil,errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block,iv)
	mode.CryptBlocks(src,src)

	return src,nil

}
func SM4CBCPKCS7Encrypt(key,src []byte) ([]byte,error) {
	tmp := pkcs7Padding(src)
	return  sm4CBCEncrypt(key,tmp)
}

func SM4CBCPKCS7EncryptWithRand(prng io.Reader,key,src []byte) ([]byte,error) {
	tmp := pkcs7Padding(src)
	return  sm4CBCEncryptWithRand(prng,key,tmp)
}

func SM4CBCPKCS7EncryptWithIV(IV []byte,key,src []byte) ([]byte,error) {
	tmp := pkcs7Padding(src)
	return sm4CBCEncryptWithIV(IV,key,tmp)
}

func SM4CBCPKCS7Decrypt(key,src []byte) ([]byte,error) {
	pt,err := sm4CBCDecrypt(key,src)

	if err == nil {
		return pkcs7UnPadding(pt)
	}
	return nil,err
}

type sm4cbcpkcs7Encryptor struct {}

func (e *sm4cbcpkcs7Encryptor) Encrypt(k bccsp.Key,plaintext []byte,opts bccsp.EncrypterOpts) ([]byte,error) {
	switch o := opts.(type) {
	case *bccsp.SM4CBCPKCS7ModeOpts:
		if len(o.IV) != 0 && o.PRNG != nil {
			return nil,errors.New("Invalid options. Either IV or PRNG should be different from nil, or both nil.")
		}

		if len(o.IV) != 0 {
			return SM4CBCPKCS7EncryptWithIV(o.IV,k.(*sm4PrivateKey).privKey,plaintext)
		} else if o.PRNG != nil {
			return SM4CBCPKCS7EncryptWithRand(o.PRNG,k.(*sm4PrivateKey).privKey,plaintext)
		}
		return SM4CBCPKCS7Encrypt(k.(*sm4PrivateKey).privKey,plaintext)
	case bccsp.SM4CBCPKCS7ModeOpts:
		return e.Encrypt(k,plaintext,&o)
	default:
		return nil,fmt.Errorf("Mode not recognized [%s]", opts)
	}
}
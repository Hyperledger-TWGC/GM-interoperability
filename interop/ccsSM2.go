package interop

import (
	"crypto/rand"

	ccs "github.com/Hyperledger-TWGC/ccs-gm/sm2"
	ccsutils "github.com/Hyperledger-TWGC/ccs-gm/utils"
)

type CCSSM2 struct {
	PrivateKey *ccs.PrivateKey
	PublicKey  *ccs.PublicKey
}

func NewCCSSM2() (*CCSSM2, error) {
	PrivateKey, err := ccs.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &CCSSM2{PrivateKey: PrivateKey, PublicKey: &PrivateKey.PublicKey}, nil
}

func CCSImportKey(privPEM []byte, pubPEM []byte) (*CCSSM2, error) {
	PrivateKey, err := ccsutils.PEMtoPrivateKey(privPEM, nil)
	if err != nil {
		return nil, err
	}
	PublicKey, err := ccsutils.PEMtoPublicKey(pubPEM, nil)
	if err != nil {
		return nil, err
	}
	return &CCSSM2{PrivateKey: PrivateKey, PublicKey: PublicKey}, nil
}

func (instance *CCSSM2) ExportKey() (privPEM []byte, pubPEM []byte, err error) {
	privPEM, err = ccsutils.PrivateKeyToPEM(instance.PrivateKey, nil)
	if err != nil {
		return
	}
	pubPEM, err = ccsutils.PublicKeyToPEM(instance.PublicKey, nil)
	return
}

func (instance *CCSSM2) Encrypt(msg []byte) ([]byte, error) {
	encrypted, err := ccs.EncryptAsn1(rand.Reader, instance.PublicKey, msg) //Instance.PublicKey.EncryptAsn1(msg, rand.Reader)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func (instance *CCSSM2) Decrypt(encrypted []byte) ([]byte, error) {
	decrypted, err := ccs.DecryptAsn1(instance.PrivateKey, encrypted)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

func (instance *CCSSM2) Sign(msg []byte) ([]byte, error) {
	sign, err := instance.PrivateKey.Sign(rand.Reader, msg, nil) // 签名
	if err != nil {
		return nil, err
	}
	return sign, nil
}

func (instance *CCSSM2) Verify(msg []byte, sign []byte) bool {
	ok := instance.PublicKey.Verify(msg, sign) // 公钥验证
	return ok
}

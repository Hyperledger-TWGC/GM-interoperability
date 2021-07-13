package workshop

import ccs "github.com/Hyperledger-TWGC/ccs-gm/sm4"

type CCSSM4 struct {
	Key []byte
}
func NewCCSSM4() (*CCSSM4, error) {
	key := []byte("0123456789abcdef")
	return &CCSSM4{Key: key}, nil
}
func (instance *CCSSM4) Encrypt(msg []byte, mode string) ([]byte, error) {
	switch mode {
	case "ecb":
		return ccs.Sm4Ecb(instance.Key, msg, ccs.ENC)
	case "cbc":
		return ccs.Sm4Cbc(instance.Key, msg, ccs.ENC)
	default:
		return ccs.Sm4Ecb(instance.Key, msg, ccs.ENC)
	}
}
func (instance *CCSSM4) Decrypt(encrypted []byte, mode string) ([]byte, error) {
	switch mode {
	case "ecb":
		return ccs.Sm4Ecb(instance.Key, encrypted, ccs.DEC)
	case "cbc":
		return ccs.Sm4Cbc(instance.Key, encrypted, ccs.DEC)
	default:
		return ccs.Sm4Ecb(instance.Key, encrypted, ccs.DEC)
	}
}

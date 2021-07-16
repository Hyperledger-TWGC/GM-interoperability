package workshop

import tj "github.com/Hyperledger-TWGC/tjfoc-gm/sm4"

type TJSM4 struct {
	Key []byte
}

func NewTJSM4() (*TJSM4, error) {
	key := []byte("0123456789abcdef")
	return &TJSM4{Key: key}, nil
}
func (instance *TJSM4) Encrypt(msg []byte, mode string) ([]byte, error) {
	switch mode {
	case "ecb":
		return tj.Sm4Ecb(instance.Key, msg, true)
	case "cbc":
		return tj.Sm4Cbc(instance.Key, msg, true)
	case "cfb":
		return tj.Sm4CFB(instance.Key, msg, true)
	case "ofb":
		return tj.Sm4OFB(instance.Key, msg, true)
	default:
		return tj.Sm4Ecb(instance.Key, msg, true)
	}
}
func (instance *TJSM4) Decrypt(encrypted []byte, mode string) ([]byte, error) {
	switch mode {
	case "ecb":
		return tj.Sm4Ecb(instance.Key, encrypted, false)
	case "cbc":
		return tj.Sm4Cbc(instance.Key, encrypted, false)
	case "cfb":
		return tj.Sm4CFB(instance.Key, encrypted, false)
	case "ofb":
		return tj.Sm4OFB(instance.Key, encrypted, false)
	default:
		return tj.Sm4Ecb(instance.Key, encrypted, false)
	}
}

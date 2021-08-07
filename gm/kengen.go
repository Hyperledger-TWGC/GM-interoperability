package gm

import (
	"crypto/rand"
	"fmt"

	"github.com/Hyperledger-TWGC/fabric-gm-plugins/gm/gmkeys"
	tj "github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"github.com/hyperledger/fabric/bccsp"
)

type TJKeyGen struct {
}

func (g *TJKeyGen) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := tj.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Failed generating GMSM2 key  [%s]", err)
	}

	return &gmkeys.TJSM2PrivateKey{Key: privKey}, nil
}

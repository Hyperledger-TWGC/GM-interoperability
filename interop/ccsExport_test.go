package interop

import (
	"crypto/rand"
	"testing"
)
import "github.com/Hyperledger-TWGC/ccs-gm/sm2"
import "github.com/Hyperledger-TWGC/ccs-gm/utils"

func TestCCSSM2PrivateKeyPemExport(t *testing.T) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	Fatal(err, t)
	pemBytes, err := utils.PrivateKeyToPEM(privKey, nil)
	Fatal(err, t)
	var pemFile = "testdata/privateKey.ccs.pem"
	WriteFile(pemBytes, pemFile, t)
}

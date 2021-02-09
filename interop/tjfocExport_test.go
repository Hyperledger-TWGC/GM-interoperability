package interop

import (
	"testing"

	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
)

func TestTJSM2Pem(t *testing.T) {
	sm2PrivKey, err := sm2.GenerateKey(nil)
	Fatal(err, t)
	pemBytes, err := x509.WritePrivateKeyToPem(sm2PrivKey, nil)
	Fatal(err, t)
	var pemFile = "testdata/privateKey.tjfoc.pem"
	WriteFile(pemBytes, pemFile, t)

}

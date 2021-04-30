package interop

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestSM2(t *testing.T) {
	sourceDef := os.Getenv("SOURCE")
	targetDef := os.Getenv("TARGET")
	action := os.Getenv("ACTION")

	base_format := "2006-01-02 15:04:05"
	time := time.Now()
	str_time := time.Format(base_format)
	msg := []byte(str_time)
	// generate key from source
	var source, target SM2
	var err error
	fmt.Println("source lib " + sourceDef)
	if sourceDef == "TJ" {
		source, err = NewTJSM2()
		Fatal(err, t)
	}
	if sourceDef == "PKU" {
		source, err = NewPKUSM2()
		Fatal(err, t)
	}
	if sourceDef == "CCS" {
		source, err = NewCCSSM2()
		Fatal(err, t)
	}
	privPEM, pubPem, err := source.ExportKey()
	Fatal(err, t)
	// locd key from target
	fmt.Println("load key to target lib " + targetDef)
	if targetDef == "TJ" {
		target, err = TJImportKey(privPEM, pubPem)
		Fatal(err, t)
	}
	if targetDef == "CCS" {
		target, err = CCSImportKey(privPEM, pubPem)
		Fatal(err, t)
	}
	if targetDef == "PKU" {
		target, err = PKUImport(privPEM, pubPem)
		Fatal(err, t)
	}

	if action == "SIGN" {
		// sign by ccs
		sign, err := target.Sign(msg)
		Fatal(err, t)
		// verify by tj
		ok := source.Verify(msg, sign) // 公钥验证
		if !ok {
			t.Fatal("source lib verify target sign error")
		}
	}
	if action == "ENCRYPT" {
		// encrypt by source
		encrypted, err := source.Encrypt(msg)
		Fatal(err, t)
		// decrypt by target
		decrypted, err := target.Decrypt(encrypted)
		if string(msg) != string(decrypted) {
			t.Fatal("soruce encrypt target decrypt error")
		}
	}
}

package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/Hyperledger-TWGC/fabric-gm-plugins/workshop"
)

var priFile = "priv.pem"

func main() {
	if os.Args[1] == "decrypt" {
		fmt.Println("decrypt")
		priv, _ := workshop.LoadFromPriPem(priFile)
		test, _ := hex.DecodeString(os.Args[2])
		decrypted, _ := priv.Decrypt(test)
		fmt.Println(string(decrypted))
	}
	if os.Args[1] == "sign" {
		fmt.Println("sign")
		priv, _ := workshop.LoadFromPriPem(priFile)
		var msg = []byte("2021-07-03 13:44:10")
		sign, _ := workshop.DegistAndSign(msg, priv)
		encodedStr := hex.EncodeToString(sign)
		fmt.Println(string(encodedStr))
	}
}

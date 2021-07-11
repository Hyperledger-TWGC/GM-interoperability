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
}

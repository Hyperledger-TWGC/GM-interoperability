package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/Hyperledger-TWGC/fabric-gm-plugins/workshop"
)

var priFile = "priv.pem"
var pubFile = "pub.pem"
var path = "./"

func main() {
	path = os.Args[1]
	if os.Args[2] == "generate" {
		fmt.Println("generate key pair at " + path)
		source, _ := workshop.GenerateSM2Instance(workshop.TJ)
		source.SaveFile(path+priFile, path+pubFile)
	}
	if os.Args[2] == "decrypt" {
		fmt.Println("decrypt")
		priv, _ := workshop.LoadFromPriPem(path + priFile)
		test, _ := hex.DecodeString(os.Args[3])
		decrypted, _ := priv.Decrypt(test)
		fmt.Println(string(decrypted))
	}
	if os.Args[2] == "sign" {
		fmt.Println("sign")
		priv, _ := workshop.LoadFromPriPem(path + priFile)
		var msg = []byte("2021-07-03 13:44:10")
		sign, _ := workshop.DegistAndSign(msg, priv)
		encodedStr := hex.EncodeToString(sign)
		fmt.Println(string(encodedStr))
	}
}

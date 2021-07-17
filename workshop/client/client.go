package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/Hyperledger-TWGC/fabric-gm-plugins/workshop"
)

var priFile = "priv.pem"
var pubFile = "pub.pem"
var path = "./"

func main() {
	// args 1 as key store path
	// args 2 as method
	// args 3 as server endpoint(optional)
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
		// generate original data
		var msg = []byte("2021-07-03 13:44:10")
		encodedMsg := hex.EncodeToString(msg)

		// do signature
		//fmt.Println(string(msg))
		//fmt.Println(string(encodedMsg))
		sign, _ := workshop.DegistAndSign(msg, priv)
		encodedStr := hex.EncodeToString(sign)
		//fmt.Println(encodedStr)
		// send to server

		bodyReader := strings.NewReader(`{"msg" : "` + string(encodedMsg) + `", "sign": "` + string(encodedStr) + `"}`)
		httpRequest, _ := http.NewRequest("POST", "http://"+os.Args[3]+"/verify", bodyReader)
		httpRequest.Header.Set("Content-Type", "application/json")
		client := http.Client{}
		response, _ := client.Do(httpRequest)
		defer response.Body.Close()
		body, _ := ioutil.ReadAll(response.Body)
		fmt.Printf(string(body))
	}
}

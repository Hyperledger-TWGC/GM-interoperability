package main

import (
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"strconv"

	"github.com/Hyperledger-TWGC/fabric-gm-plugins/workshop"
	restful "github.com/emicklei/go-restful/v3"
)

var pubFile = "pub.pem"

func main() {
	ws := new(restful.WebService)
	ws.Route(ws.GET("/verify").To(verify))
	ws.Route(ws.GET("/encrypt").To(encrypt))
	restful.Add(ws)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func verify(req *restful.Request, resp *restful.Response) {
	var Key workshop.SM2
	Key, _ = workshop.LoadFromPubPem(pubFile)
	var msg = []byte("2021-07-03 13:44:10")
	//todo get sign from request
	dummy, _ := hex.DecodeString("304502201fdfdeaee05eb78013adf283f65de61d50adf7b6a792d41c994ed4a36775355b022100d6873ec4c6ebcf5ac97b88990ba1e0a9abe4e06f37e0cd05ef07849f7d24c519")
	data := workshop.DegistAndVerify(msg, dummy, Key)
	log.Println(data)
	//todo string data is not human-readable
	io.WriteString(resp, strconv.FormatBool(data))
}

func encrypt(req *restful.Request, resp *restful.Response) {
	var Key workshop.SM2
	Key, _ = workshop.LoadFromPubPem(pubFile)
	var msg = []byte("2021-07-03 13:44:10")
	data, _ := Key.Encrypt(msg)
	log.Println(data)
	encodedStr := hex.EncodeToString(data)
	log.Println(encodedStr)
	//todo string data is not human-readable
	io.WriteString(resp, encodedStr)
}

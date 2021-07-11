package main

import (
	"encoding/hex"
	"io"
	"log"
	"net/http"

	"github.com/Hyperledger-TWGC/fabric-gm-plugins/workshop"
	restful "github.com/emicklei/go-restful/v3"
)

var pubFile = "pub.pem"

func main() {
	ws := new(restful.WebService)
	ws.Route(ws.POST("/verify").To(verify))
	ws.Route(ws.GET("/encrypt").To(encrypt))
	restful.Add(ws)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func verify(req *restful.Request, resp *restful.Response) {
	var Key workshop.SM2
	Key, _ = workshop.LoadFromPubPem(pubFile)
	var msg = []byte("2021-07-03 13:44:10")
	//todo get sign from request
	data := workshop.DegistAndVerify(msg, nil, Key)
	log.Println(data)
	//todo string data is not human-readable
	io.WriteString(resp, "data")
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

package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/Hyperledger-TWGC/fabric-gm-plugins/workshop"
	restful "github.com/emicklei/go-restful/v3"
)

var pubFile = "pub.pem"
var path = "./"
var Key workshop.SM2
var err error

type Anything map[string]interface{}

func main() {
	path = os.Args[1]
	ws := new(restful.WebService)
	ws.Route(ws.POST("/verify").To(verify))
	ws.Route(ws.GET("/encrypt").To(encrypt))
	restful.Add(ws)
	Key, err = workshop.LoadFromPubPem(path + pubFile)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("start server")
	}
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", nil))
}

func verify(req *restful.Request, resp *restful.Response) {
	log.Println("verify")
	//get origin data from request
	any := make(Anything)
	req.ReadEntity(&any)
	//fmt.Println(any)
	msg, ok := any["msg"].(string)
	if !ok {
		fmt.Println("read failed")
	}
	sign, ok := any["sign"].(string)
	if !ok {
		fmt.Println("read failed")
	}
	originalmsg, _ := hex.DecodeString(msg)

	//get signature from request
	dummy, _ := hex.DecodeString(sign)
	//do verify
	//fmt.Println(originalmsg)
	data := workshop.DegistAndVerify([]byte(originalmsg), dummy, Key)
	//return
	io.WriteString(resp, strconv.FormatBool(data))
}

func encrypt(req *restful.Request, resp *restful.Response) {
	log.Println("encrypt")
	now := time.Now()
	year, month, day := now.Date()
	today_str := fmt.Sprintf("%d-%d-%d 00:00:00", year, month, day)
	var msg = []byte(today_str)
	encodedMsg := hex.EncodeToString(msg)
	data, _ := Key.Encrypt(msg)
	encodedStr := hex.EncodeToString(data)
	//log.Println(encodedStr)
	//todo string data is not human-readable
	io.WriteString(resp, `{"msg" : "`+string(encodedMsg)+`", "encrypt": "`+string(encodedStr)+`"}`)
}

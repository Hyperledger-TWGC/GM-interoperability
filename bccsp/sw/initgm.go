package sw

import (
	//fabric_gm_plugins_sm4 "github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm4"
	"sync"
)

//var sm4 core.SM4

//var sm3 core.SM3

//var sm4 fabric_gm_plugins.SM4Type

var initonce sync.Once
func init(){
	initonce.Do(initALL)
}

func initALL(){
	//sm4= core.NewSM4()
	//sm2.PrivateKey=sm2.PrivateKey{fabric_gm_plugins_sm2.NewSM2Private()}
	//sm3= fabric_gm_plugins_sm3.NewSM3()
}
/*
Copyright Hyperledger - Technical Working Group China. 2020 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package sm3

import (
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core"
	tjfoc_gm "github.com/Hyperledger-TWGC/fabric-gm-plugins/core/tjfoc-gm"
	"hash"
	"log"
)

/**
Author: yzwyzwyzw1(Github ID)
email: 1957855254@qq.com
*/


func New() hash.Hash {

	var gmopts string=core.NewGM()
	switch gmopts {
	case "tjfoc-gm":{
		log.Println("tjfoc-gm-sm3")
		return tjfoc_gm.NewSM3()
	}
		//case "ccs-gm":{
		//
		//}
		//case "pku-gm":{
		//
		//}
	default:{
		return tjfoc_gm.NewSM3()
	}
	}
}


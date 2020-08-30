package sw

import (
	"fmt"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm4"
	"testing"
)

func TestNewSM4(t *testing.T){
	fmt.Println(sm4.BlockSize)
	var key =[]byte("1234567890abcdef")
	a,err:=sm4.NewCipher(key)
	if err != nil{
		fmt.Println("123")
	}
	fmt.Println(a)

}


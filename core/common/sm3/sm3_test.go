package sm3

import (
	"log"
	"testing"
)

//间接调用测试
func TestSM3(t *testing.T) {
	hash:=New()
	msg := []byte("test")
	hash.Write(msg)
	log.Println("hash: ",hash.Sum(nil))
}



package tjfoc_gm

import (
	"fmt"
	"reflect"
	"testing"
)

func TestSM3(t *testing.T){

	fmt.Println(reflect.TypeOf(NewSM3().BlockSize()))
}

func TestSm3(t *testing.T) {
	msg := []byte("test")
	hw := NewSM3()
	hw.Write(msg)
	hash := hw.Sum(nil)
	fmt.Println(hash)
}
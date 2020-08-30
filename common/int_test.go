package common

import (
	"fmt"
	"hash"
	"reflect"
	"testing"
)

type SM3_I interface {
	Write(p []byte) (int, error)
	Sum(in []byte) []byte
	BlockSize() int
	Size() int
	Reset()
}


func TestInt(t *testing.T){
	var a SM3_I
	var b hash.Hash
	fmt.Println("interface a type: ",reflect.ValueOf(a))
	fmt.Println("interface b type: ",reflect.ValueOf(b))
    //ty:=reflect.ValueOf(a)
    //var dd=ty.
    //fmt.Println(dd)
	//fmt.Println("interface a Elem: ",reflect.ValueOf(a).Elem())
	//reflect.ValueOf(a).Elem()
	fmt.Println("interface b type: ",reflect.ValueOf(b))
	fmt.Println(reflect.DeepEqual(a,b))
}


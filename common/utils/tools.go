package utils

import (
	"crypto/cipher"
	"fmt"
	"reflect"
)

// func1(...) (a []byte,err error)
func InterfaceToType1(parms []interface{}) (a []byte,err error){

	a=parms[0].([]byte)
	err=parms[1].(error)
	return a,err
}

// func1(...) (a cipher.Block,err error)
func InterfaceToType2(parms []interface{}) (a cipher.Block,err error){

	fmt.Println(reflect.TypeOf(parms[0]))
	a=parms[0].(cipher.Block)
	if parms[1]==nil{
		err=nil
	}else{
		err=parms[1].(error)
	}

	return a,err
}
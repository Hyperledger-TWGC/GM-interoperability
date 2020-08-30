package core

//
//type SM3 interface {
//	Write(p []byte) (int, error)
//	Sum(in []byte) []byte
//	BlockSize() int
//	Size() int
//	Reset()
//}
//
//func NewSM3() SM3 {
//
//	var gmopts string=NewGM()
//	switch gmopts {
//	case "tjfoc-gm":{
//		return tjfoc_gm.NewSM3()
//	}
//		//case "ccs-gm":{
//		//
//		//}
//		//case "pku-gm":{
//		//
//		//}
//	default:{
//		return tjfoc_gm.NewSM3()
//	}
//	}
//}

//type SM4 interface {
//	BlockSize() int
//	Encrypt(dst, src []byte)
//	Decrypt(dst, src []byte)
//
//	//Transform
//	//invoke other function
//	Transform(str string,parms ...interface{}) []interface{}
//}
//
//func NewSM4()  SM4{
//
//	var gmopts string=NewGM()
//	switch gmopts {
//	case "tjfoc-gm":{
//		return tjfoc_gm.NewSM4()
//	}
//		//case "ccs-gm":{
//		//
//		//}
//		//case "pku-gm":{
//		//
//		//}
//	default:{
//		return tjfoc_gm.NewSM4()
//	}
//	}
//}
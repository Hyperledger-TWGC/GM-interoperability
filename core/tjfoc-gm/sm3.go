package tjfoc_gm

import (
	tjfoc_gm_sm3 "github.com/Hyperledger-TWGC/tjfoc-gm/sm3"
	"hash"
)


var sm3 tjfoc_gm_sm3.SM3



//type SM3_I interface {
//	Write(p []byte) (int, error)
//	Sum(in []byte) []byte
//	BlockSize() int
//	Size() int
//	Reset()
//}

type SM3 struct {

}

func (c *SM3)Sum(in []byte) []byte {
	return  sm3.Sum(in)
}

func (c *SM3)Write(p []byte) (int,error){
	return sm3.Write(p)
}

func (c *SM3)Size() int{
	return sm3.Size()
}

func (c *SM3)Reset(){
	sm3.Reset()
}
func (c *SM3)BlockSize() int{
	return sm3.BlockSize()
}

//func NewSM3() SM3_I  {
//
//	return &SM3{}
//}


func NewSM3() hash.Hash  {

	return  tjfoc_gm_sm3.New()

	//var sm3 tjfoc_gm_sm3.SM3
	//sm3.Reset()
	//return sm3
}
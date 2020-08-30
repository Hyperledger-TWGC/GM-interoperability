package tjfoc_gm

import (
	"crypto"
	"crypto/elliptic"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
)
type PublicKey_I interface {
	Verify(msg []byte, sign []byte) bool
	Encrypt(data []byte) ([]byte, error)
}

type PrivateKey_I interface {
	Sign(msg []byte, uid []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
}



var sm2_Priv sm2.PrivateKey
type PrivateKey struct {
	sm2.PrivateKey
}

var sm2_Pub sm2.PublicKey
type PublicKey struct {
	sm2.PublicKey
}

func (pub *PublicKey) Verify(msg []byte, sign []byte) bool {
	sm2_Pub.X=pub.X
	sm2_Pub.Y=pub.Y
	sm2_Pub.Curve=pub.Curve
	return sm2_Pub.Verify(msg,sign)
}

func (priv *PrivateKey) Sign(msg []byte, uid []byte) ([]byte, error) {
	sm2_Priv.X=priv.X
	sm2_Priv.Y=priv.Y
	sm2_Priv.D=priv.D
	sm2_Priv.Curve=priv.Curve
	return sm2_Priv.Sign(msg,uid)
}

func (pub *PublicKey) Encrypt(data []byte) ([]byte, error) {
	sm2_Pub.X=pub.X
	sm2_Pub.Y=pub.Y
	sm2_Pub.Curve=pub.Curve
	return sm2_Pub.Encrypt(data)
}

func (priv *PrivateKey) Decrypt(data []byte) ([]byte, error) {
	sm2_Priv.X=priv.X
	sm2_Priv.Y=priv.Y
	sm2_Priv.D=priv.D
	sm2_Priv.Curve=priv.Curve
	return sm2_Priv.Decrypt(data)
}


func (priv *PrivateKey) Public() crypto.PublicKey  {
	sm2_Priv.X=priv.X
	sm2_Priv.Y=priv.Y
	sm2_Priv.D=priv.D
	sm2_Priv.Curve=priv.Curve
	return sm2_Priv.PublicKey
}

func NewSM2PublicKey() PublicKey_I{
	return &sm2.PublicKey{}
}

func NewSM2PrivateKey() PrivateKey_I{
	return &sm2.PrivateKey{}
}
func GenerateKey() (*sm2.PrivateKey, error) {
	return sm2.GenerateKey()
}
func P256() elliptic.Curve{
	return sm2.P256Sm2()
}
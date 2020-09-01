package tjfoc_gm

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"io"
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
	return sm2_Priv.Sign(rand.Reader,msg,nil)
}

func (pub *PublicKey) Encrypt(data []byte) ([]byte, error) {
	sm2_Pub.X=pub.X
	sm2_Pub.Y=pub.Y
	sm2_Pub.Curve=pub.Curve
	return sm2_Pub.Encrypt(data,rand.Reader)
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
	return &PublicKey{}
}

func NewSM2PrivateKey() PrivateKey_I{
	return &PrivateKey{}
}
func GenerateKey(rand io.Reader) (*sm2.PrivateKey, error) {
	return sm2.GenerateKey(rand)
}
func P256() elliptic.Curve{
	return sm2.P256Sm2()
}
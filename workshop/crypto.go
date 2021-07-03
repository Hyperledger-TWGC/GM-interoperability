package workshop

import tjsm3 "github.com/Hyperledger-TWGC/tjfoc-gm/sm3"

func DegistAndSign(msg []byte, priv SM2) ([]byte, error) {
	tj_digest := tjsm3.Sm3Sum(msg)
	return priv.Sign(tj_digest)
}

func DegistAndVerify(msg, sign []byte, pub SM2) bool {
	tj_digest := tjsm3.Sm3Sum(msg)
	return pub.Verify(tj_digest, sign)
}

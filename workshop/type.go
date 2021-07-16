package workshop

type SM2 interface {
	Encrypt(msg []byte) ([]byte, error)
	Decrypt(encrypted []byte) ([]byte, error)
	Sign(msg []byte) ([]byte, error)
	Verify(msg []byte, sign []byte) bool
	ExportKey() (privPEM []byte, pubPEM []byte, err error)
	SaveFile(priFile, pubFile string) error
}
type SM4 interface{
	Encrypt(msg []byte,mode string)([]byte,error)
	Decrypt(encrypted []byte,mode string)([]byte,error)
}
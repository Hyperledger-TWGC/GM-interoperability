package fabric_gm_plugins

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
)

/**
Author: ghostchen47
*/
type X509Interface interface {
	NewCertPool() *x509.CertPool
	IsEncryptedPEMBlock(b *pem.Block) bool
	DecryptPEMBlock(b *pem.Block, password []byte) ([]byte, error)
	EncryptPEMBlock(rand io.Reader, blockType string, data, password []byte, alg x509.PEMCipher) (*pem.Block, error) // TODO alg x509.PEMCipher -> alg string
	ParseCertificate(asn1Data []byte) (*x509.Certificate, error)
	CreateCertificate(rand io.Reader, template, parent *x509.Certificate, pub, priv interface{}) (cert []byte, err error)
	ParseCRL(crlBytes []byte) (*pkix.CertificateList, error)
}

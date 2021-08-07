package gmkeys_test

import (
	"crypto/rand"

	"github.com/Hyperledger-TWGC/fabric-gm-plugins/gm/gmkeys"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	tj "github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
)

var _ = Describe("Key", func() {

	Context("TJ Private", func() {
		TJPrivateKey, err := tj.GenerateKey(rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		Intance := &gmkeys.TJSM2PrivateKey{
			Key: TJPrivateKey,
		}
		It("Bytes", func() {
			data, err := Intance.Bytes()
			Expect(err).NotTo(HaveOccurred())
			Expect(len(data)).NotTo(Equal(0))
		})

		It("SKI", func() {
			Expect(len(Intance.SKI())).NotTo(Equal(0))
		})

		It("Symmetric", func() {
			Expect(false).To(Equal(Intance.Symmetric()))
		})

		It("Private", func() {
			Expect(true).To(Equal(Intance.Private()))
		})

		It("PublicKey", func() {
			pubkey, err := Intance.PublicKey()
			Expect(err).NotTo(HaveOccurred())
			data, err := pubkey.Bytes()
			Expect(err).NotTo(HaveOccurred())
			Expect(len(data)).NotTo(Equal(0))
		})
	})

	Context("TJ Public", func() {
		TJPrivateKey, err := tj.GenerateKey(rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		TJSM2Publickey := &TJPrivateKey.PublicKey
		Intance := &gmkeys.TJSM2Publickey{
			Key: TJSM2Publickey,
		}

		It("Bytes", func() {
			data, err := Intance.Bytes()
			Expect(err).NotTo(HaveOccurred())
			Expect(len(data)).NotTo(Equal(0))
		})

		It("SKI", func() {
			Expect(len(Intance.SKI())).NotTo(Equal(0))
		})

		It("Symmetric", func() {
			Expect(false).To(Equal(Intance.Symmetric()))
		})

		It("Private", func() {
			Expect(false).To(Equal(Intance.Private()))
		})

		It("PublicKey", func() {
			pubkey, err := Intance.PublicKey()
			Expect(err).NotTo(HaveOccurred())
			data, err := pubkey.Bytes()
			Expect(err).NotTo(HaveOccurred())
			Expect(len(data)).NotTo(Equal(0))
		})
	})
	/* to do
	Context("CCS private", func() {
		It("Bytes", func() {

		})

		It("SKI", func() {

		})

		It("Symmetric", func() {

		})

		It("Private", func() {

		})

		It("PublicKey", func() {

		})
	})

	Context("CCS public", func() {
		It("Bytes", func() {

		})

		It("SKI", func() {

		})

		It("Symmetric", func() {

		})

		It("Private", func() {

		})

		It("PublicKey", func() {

		})
	})
	*/
})

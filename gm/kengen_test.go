package gm_test

import (
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/gm"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Kengen", func() {
	It("should able to generate tj key", func() {
		instance := &gm.TJKeyGen{}
		key, err := instance.KeyGen(nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(true).To(Equal(key.Private()))
	})
})

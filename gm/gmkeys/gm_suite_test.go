package gmkeys_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestGm(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Gm Suite")
}

package gm_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestBccsp(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Bccsp Suite")
}

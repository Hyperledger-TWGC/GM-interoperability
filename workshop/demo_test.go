package workshop_test

import (
	"io/ioutil"
	"os"
	"os/exec"

	"github.com/onsi/gomega/gexec"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
)

var (
	PrivFile, PubFile            *os.File
	tmpDir, serverBin, clientBin string
	serverSession, clientSession *gexec.Session
)

var _ = Describe("Server", func() {

	BeforeSuite(func() {
		tmpDir, err = ioutil.TempDir("", "workshop-e2e-")
		Expect(err).NotTo(HaveOccurred())

		serverBin, err = gexec.Build("./server")
		Expect(err).NotTo(HaveOccurred())

		clientBin, err = gexec.Build("./client")
		Expect(err).NotTo(HaveOccurred())
	})

	BeforeEach(func() {
		cmd := exec.Command(clientBin, tmpDir, "generate")
		clientSession, err = gexec.Start(cmd, nil, nil)
		Eventually(clientSession.Out).Should(Say("generate key pair at " + tmpDir))
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		if serverSession != nil && serverSession.ExitCode() == -1 {
			serverSession.Kill()
		}

		if clientSession != nil && clientSession.ExitCode() == -1 {
			clientSession.Kill()
		}
	})

	AfterSuite(func() {
		os.RemoveAll(tmpDir)
		os.Remove(serverBin)
		os.Remove(clientBin)
	})

	// start server with public key via tj
	Context("init functions", func() {
		It("should start server", func() {
			cmd := exec.Command(serverBin, tmpDir)
			serverSession, err = gexec.Start(cmd, nil, nil)
			Eventually(serverSession.Out).Should(Say("start server"))
			Expect(err).NotTo(HaveOccurred())
		})
	})

	// client send request via private key vai ccs
	Context("server client interact", func() {
		It("sign interact", func() {})
		It("verfiy interact", func() {})
		It("encrypt interact", func() {})
		It("decrypt interact", func() {})
		It("sm4 interact", func() {})
	})
})

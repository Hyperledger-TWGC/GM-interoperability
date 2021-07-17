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
		if serverSession != nil {
			serverSession.Kill()
		}

		if clientSession != nil {
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
		It("verfiy & sign interact", func() {
			server_cmd := exec.Command(serverBin, tmpDir)
			serverSession, err = gexec.Start(server_cmd, nil, nil)
			Expect(err).NotTo(HaveOccurred())
			Eventually(serverSession.Out).Should(Say("start server"))

			client_cmd := exec.Command(clientBin, tmpDir, "sign", "127.0.0.1:8080")
			clientSession, err = gexec.Start(client_cmd, nil, nil)
			Expect(err).NotTo(HaveOccurred())
			Eventually(clientSession.Out).Should(Say("sign"))

			//Eventually(serverSession.Out).Should(Say("verify"))

			Eventually(clientSession.Out).Should(Say("true"))
		})
		It("decrypt & encrypt interact", func() {
			server_cmd := exec.Command(serverBin, tmpDir)
			serverSession, err = gexec.Start(server_cmd, nil, nil)
			Expect(err).NotTo(HaveOccurred())
			Eventually(serverSession.Out).Should(Say("start server"))

			client_cmd := exec.Command(clientBin, tmpDir, "decrypt", "127.0.0.1:8080")
			clientSession, err = gexec.Start(client_cmd, nil, nil)
			Expect(err).NotTo(HaveOccurred())
			Eventually(clientSession.Out).Should(Say("decrypt"))

			//Eventually(serverSession.Out).Should(Say("verify"))

			Eventually(clientSession.Out).Should(Say("true"))
		})
		It("sm4 interact", func() {})
	})
})

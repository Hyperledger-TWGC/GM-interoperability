package factory

import (
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestGMFactoryName(t *testing.T) {
	f := &GMSWFactory{}
	assert.Equal(t, f.Name(), gmSoftwareBasedFactoryName)
}

func TestGMSWFactoryGetInvalidArgs(t *testing.T) {
	f := &GMSWFactory{}

	_, err := f.Get(nil)
	assert.Error(t, err, "Invalid config. It must not be nil.")

	_, err = f.Get(&factory.FactoryOpts{})
	assert.Error(t, err, "Invalid config. It must not be nil.")

	opts := &factory.FactoryOpts{
		SW: &factory.SwOpts{},
	}
	_, err = f.Get(opts)
	assert.Error(t, err, "CSP:500 - Failed initializing configuration at [0,]")
}

func TestGMSWFactoryGet(t *testing.T) {
	f := &GMSWFactory{}

	opts := &factory.FactoryOpts{
		SW: &factory.SwOpts{
			Security: 256,
			Hash:     "SM3",
		},
	}
	csp, err := f.Get(opts)
	assert.NoError(t, err)
	assert.NotNil(t, csp)

	opts = &factory.FactoryOpts{
		SW: &factory.SwOpts{
			Security: 256,
			Hash:     "SM3",
			FileKeystore: &factory.FileKeystoreOpts{KeyStorePath: os.TempDir()},
		},
	}
	csp, err = f.Get(opts)
	assert.NoError(t, err)
	assert.NotNil(t, csp)

}


package factory

import (
	gmsw "github.com/Hyperledger-TWGC/fabric-gm-plugins/bccsp/sw"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/pkg/errors"
)

const (
	gmSoftwareBasedFactoryName = "GMSW"
)


type GMSWFactory struct{}

func (f *GMSWFactory) Name() string {
	return gmSoftwareBasedFactoryName
}


// Get returns an instance of BCCSP using Opts.
func (f *GMSWFactory) Get(config *factory.FactoryOpts) (bccsp.BCCSP, error) {
	// Validate arguments
	if config == nil || config.SW == nil {
		return nil, errors.New("Invalid config. It must not be nil.")
	}

	swOpts := config.SW
	var ks bccsp.KeyStore
	switch {
	case swOpts.FileKeystore != nil:
		fks, err := gmsw.NewFileBasedKeyStore(nil, swOpts.FileKeystore.KeyStorePath, false)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to initialize software key store")
		}
		ks = fks
	default:
		// Default to ephemeral key store
		ks = sw.NewDummyKeyStore()
	}

	return gmsw.NewWithParams(swOpts.Security, swOpts.Hash, ks)
}


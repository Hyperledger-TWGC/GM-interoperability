/*
Copyright Hyperledger - Technical Working Group China. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sw

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/Hyperledger-TWGC/fabric-gm-plugins/core/common/sm2"
	"github.com/stretchr/testify/require"

	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestInvalidStoreKey(t *testing.T) {
	t.Parallel()

	tempDir, err := ioutil.TempDir("", "bccspks")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	ks, err := NewFileBasedKeyStore(nil, filepath.Join(tempDir, "bccspks"), false)
	if err != nil {
		fmt.Printf("Failed initiliazing KeyStore [%s]", err)
		os.Exit(-1)
	}

	err = ks.StoreKey(nil)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&sm2PrivateKey{nil})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&sm2PublicKey{nil})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&sm4PrivateKey{nil, false})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&sm4PrivateKey{nil, true})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
}

func TestBigKeyFile(t *testing.T) {
	ksPath, err := ioutil.TempDir("", "bccspks")
	require.NoError(t, err)
	defer os.RemoveAll(ksPath)

	ks, err := NewFileBasedKeyStore(nil, ksPath, false)
	require.NoError(t, err)

	// Generate a key for keystore to find
	privKey, err := sm2.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cspKey := &sm2PrivateKey{privKey}
	ski := cspKey.SKI()

	rawKey, err := privateKeyToPEM(privKey, nil)
	require.NoError(t, err)


	// Large padding array, of some values PEM parser will NOOP
	bigBuff := make([]byte, (1 << 17))
	for i := range bigBuff {
		bigBuff[i] = '\n'
	}
	copy(bigBuff, rawKey)

	//>64k, so that total file size will be too big
	ioutil.WriteFile(filepath.Join(ksPath, "bigfile.pem"), bigBuff, 0666)

	_, err = ks.GetKey(ski)
	require.Error(t, err)
	expected := fmt.Sprintf("Key with SKI %s not found in %s", hex.EncodeToString(ski), ksPath)
	require.EqualError(t, err, expected)

	// 1k, so that the key would be found
	//ioutil.WriteFile(filepath.Join(ksPath, "smallerfile.pem"), bigBuff[0:1<<10], 0666)
	//
	//_, err = ks.GetKey(ski) // 存储报错
	//require.NoError(t, err)
}

func TestReInitKeyStore(t *testing.T) {
	ksPath, err := ioutil.TempDir("", "bccspks")
	require.NoError(t, err)
	defer os.RemoveAll(ksPath)

	ks, err := NewFileBasedKeyStore(nil, ksPath, false)
	require.NoError(t, err)
	fbKs, isFileBased := ks.(*fileBasedKeyStore)
	require.True(t, isFileBased)
	err = fbKs.Init(nil, ksPath, false)
	require.EqualError(t, err, "keystore is already initialized")
}

func TestDirExists(t *testing.T) {
	r, err := dirExists("")
	require.False(t, r)
	require.NoError(t, err)

	r, err = dirExists(os.TempDir())
	require.NoError(t, err)
	require.Equal(t, true, r)

	r, err = dirExists(filepath.Join(os.TempDir(), "7rhf90239vhev90"))
	require.NoError(t, err)
	require.Equal(t, false, r)
}


func TestDirEmpty(t *testing.T) {
	_, err := dirEmpty("")
	require.Error(t, err)

	path := filepath.Join(os.TempDir(), "7rhf90239vhev90")
	defer os.Remove(path)
	os.Mkdir(path, os.ModePerm)

	r, err := dirEmpty(path)
	require.NoError(t, err)
	require.Equal(t, true, r)

	r, err = dirEmpty(os.TempDir())
	require.NoError(t, err)
	require.Equal(t, false, r)
}

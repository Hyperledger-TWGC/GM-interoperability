package interop

import (
	"testing"
	"time"

	ccs "github.com/Hyperledger-TWGC/ccs-gm/sm3"
	pku "github.com/Hyperledger-TWGC/pku-gm/gmssl"
	tj "github.com/Hyperledger-TWGC/tjfoc-gm/sm3"
)

const base_format = "2006-01-02 15:04:05"

func TestSM3(t *testing.T) {
	// generate a random string as data
	time := time.Now()
	str_time := time.Format(base_format)
	msg := []byte(str_time)
	// generate key from tj
	tj_digest := tj.Sm3Sum([]byte(str_time))
	ccs_digest := ccs.SumSM3(msg)
	sm3hash := pku.New()
	sm3hash.Write(msg)
	pku_digest:=sm3hash.Sum(nil)
	if string(tj_digest)!=string(ccs_digest){
		t.Error("error, tj digest doesn't equal with ccs digest")
	}
	if string(ccs_digest)!=string(pku_digest){
		t.Error("error, ccs digest doesn't equal with pku digest")
	}
}

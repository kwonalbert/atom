package trustee

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/rpc"
	"sync"
	"testing"
	"time"

	"github.com/kwonalbert/atom/directory"

	. "github.com/kwonalbert/atom/atomrpc"
	. "github.com/kwonalbert/atom/common"
	. "github.com/kwonalbert/atom/crypto"
)

var addr string = "127.0.0.1:%d"
var dirPort = 8000
var port = 8001

var testNet = SQUARE
var testMode = TRAP_MODE

var numServers = 0
var numGroups = 1
var perGroup = 3
var numTrustees = 2

var numMsgs = 4
var msgSize = 5
var threshold = perGroup
var numClients = 0

func setup() (*directory.Directory, []*Trustee, error) {
	dir, err := directory.NewDirectory(0, dirPort, testMode, testNet,
		numServers, numGroups, perGroup, numTrustees,
		numMsgs, msgSize, threshold,
		numClients)
	if err != nil {
		return nil, nil, err
	}
	go dir.Close()
	time.Sleep(100 * time.Millisecond)

	trustees := make([]*Trustee, numTrustees)

	dirAddrs := []string{fmt.Sprintf(addr, dirPort)}

	wg := new(sync.WaitGroup)
	for i := range trustees {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var err error
			trustees[i], err = NewTrustee(fmt.Sprintf(addr, port+i), i,
				"", dirAddrs)
			if err != nil {
				log.Fatal("Trustee creation err:", err)
			}

			trustees[i].Setup()

			if i == 0 {
				fmt.Println("Generating per round keys")
			}
			trustees[i].RegisterRound()

			if i == 0 {
				fmt.Println("Finished trustee setup")
			}
		}(i)
	}
	wg.Wait()
	return dir, trustees, nil
}

func TestReport(t *testing.T) {
	_, trustees, err := setup()
	if err != nil {
		t.Error(err)
	}

	// correct report
	report := ReportArgs{
		Round:        0,
		Sid:          0,
		Uid:          0,
		CorrectHash:  true,
		CorrectTraps: true,
		NumTraps:     128,
		NumMsgs:      128,
	}

	_, tlsConfig := AtomTLSConfig()

	replies := make([]*PrivateKey, numGroups*perGroup)
	repliesLock := make([]*sync.Mutex, numGroups*perGroup)
	for r := range replies {
		repliesLock[r] = new(sync.Mutex)
	}

	wg := new(sync.WaitGroup)
	for u := range trustees { // report to each trustee
		for i := 0; i < numGroups*perGroup; i++ { // each member reports
			wg.Add(1)
			go func(i, u int) {
				defer wg.Done()
				conn, err := tls.Dial("tcp", fmt.Sprintf(addr, port+u), tlsConfig)
				if err != nil {
					t.Error(err)
				}
				trustee := rpc.NewClient(conn)
				var reply ReportReply
				err = trustee.Call("TrusteeRPC.Report", &report, &reply)
				if err != nil {
					t.Error(err)
				}
				repliesLock[i].Lock()
				if replies[i] == nil {
					replies[i] = reply.Priv
				} else {
					tmp := []*PrivateKey{replies[i], reply.Priv}
					replies[i] = CombinePrivateKeys(tmp)
				}
				repliesLock[i].Unlock()
				trustee.Close()
			}(i, u)
		}
		wg.Wait()
	}

	for r := range replies {
		for u := range trustees {
			exp := CombinePublicKeys(trustees[u].publicKeys)
			res := PubFromPriv(replies[r])
			if !res.Equal(exp) {
				t.Error("Failed to recover trustee keys")
			}
		}
	}
}

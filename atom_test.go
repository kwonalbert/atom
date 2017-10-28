package atom

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/pprof"
	"sync"
	"testing"

	"github.com/kwonalbert/atom/client"
	"github.com/kwonalbert/atom/db"
	"github.com/kwonalbert/atom/directory"
	"github.com/kwonalbert/atom/server"
	"github.com/kwonalbert/atom/trustee"

	. "github.com/kwonalbert/atom/common"
	. "github.com/kwonalbert/atom/crypto"
)

var addr = "127.0.0.1:%d"
var dirPort = 8000
var port = 8001
var trusteePort = 9001
var dbPort = 10001

var testNet = SQUARE

var numServers = 9
var numGroups = 4
var perGroup = 6
var numTrustees = 2
var faultTolerence = 1

var numMsgs = 16
var msgSize = 10 // in bytes
var threshold = perGroup - faultTolerence
var numClients = numGroups

var cpuprofile = "cpuprofile"

func memberMessage(msg Message, msgs []Message) bool {
	for m := range msgs {
		if msg.Equal(msgs[m]) {
			return true
		}
	}
	return false
}

// Should call defer pprof.StopCPUProfile() for the test as well
func profile() {
	flag.Parse()
	if cpuprofile != "" {
		f, err := os.Create(cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
	}
}

func TestNIZKMixing(t *testing.T) {
	dir, _, servers, clients, db := setup(VER_MODE)

	plaintextss := make([][][]byte, len(clients))
	for c := range clients {
		plaintextss[c] = make([][]byte, numMsgs)
		for p := range plaintextss[c] {
			plaintextss[c][p] = make([]byte, msgSize)
			rand.Read(plaintextss[c][p])
		}
	}

	results := make(chan [][]byte, len(clients))
	for c := range clients {
		go func(c int) {
			clients[c].Submit(c, 0, plaintextss[c])
			res, err := clients[c].DownloadMsgs(0)
			if err != nil {
				t.Error(err)
			}
			results <- res
		}(c)
	}

	var exp [][]byte
	for _, plaintexts := range plaintextss {
		exp = append(exp, plaintexts...)
	}

	for _ = range clients {
		res := <-results
		for r := range res {
			if !MemberByteSlice(res[r], exp) {
				t.Error("Missing plaintexts")
			}
		}
	}

	dir.Close()
	db.Close()
	for _, server := range servers {
		server.Close()
	}
}

func TestTrapMixing(t *testing.T) {
	//profile()
	//defer pprof.StopCPUProfile()
	dir, trustees, servers, clients, db := setup(TRAP_MODE)

	plaintextss := make([][][]byte, len(clients))
	for c := range clients {
		plaintextss[c] = make([][]byte, numMsgs)
		for p := range plaintextss[c] {
			plaintextss[c][p] = make([]byte, msgSize)
			rand.Read(plaintextss[c][p])
		}
	}

	results := make(chan [][]byte, len(clients))
	for c := range clients {
		go func(c int) {
			clients[c].Submit(c, 0, plaintextss[c])
			res, err := clients[c].DownloadMsgs(0)
			if err != nil {
				t.Error(err)
			}
			results <- res
		}(c)
	}

	var exp [][]byte
	for _, plaintexts := range plaintextss {
		exp = append(exp, plaintexts...)
	}

	for _ = range clients {
		res := <-results
		for r := range res {
			if !MemberByteSlice(res[r], exp) {
				t.Error("Missing plaintexts")
			}
		}
	}

	dir.Close()
	db.Close()
	for _, trustee := range trustees {
		trustee.Close()
	}
	for _, server := range servers {
		server.Close()
	}
}

func setup(testMode int) (*directory.Directory, []*trustee.Trustee, []*server.Server, []*client.Client, *db.DB) {
	numTrustees_ := numTrustees
	if testMode == VER_MODE {
		numTrustees_ = 0
	}

	wg := new(sync.WaitGroup)

	dir, err := directory.NewDirectory(0, dirPort, testMode, testNet,
		numServers, numGroups, perGroup, numTrustees_,
		numMsgs, msgSize, threshold,
		numClients)
	if err != nil {
		log.Fatal("Directory creation err:", err)
	}

	db, err := db.NewDB(dbPort)
	if err != nil {
		log.Fatal("DB creation err:", err)
	}

	trustees := make([]*trustee.Trustee, numTrustees_)
	servers := make([]*server.Server, numServers)
	clients := make([]*client.Client, numGroups)

	dirAddrs := []string{fmt.Sprintf(addr, dirPort)}
	dbAddr := fmt.Sprintf(addr, dbPort)

	// start the servers
	for i := range servers {
		servers[i], err = server.NewServer(fmt.Sprintf(addr, port+i), i,
			"", dirAddrs, dbAddr)
		if err != nil {
			log.Fatal("Server creation err:", err)
		}
	}

	for i := range trustees {
		trustees[i], err = trustee.NewTrustee(fmt.Sprintf(addr, trusteePort+i), i,
			"", dirAddrs)
		if err != nil {
			log.Fatal("Trustee creation err:", err)
		}
	}

	// connect the servers and setup group keys
	for i := range servers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			servers[i].Setup()
		}(i)
	}

	// start the trustees
	for i := range trustees {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			trustees[i].Setup()
			trustees[i].RegisterRound()
		}(i)
	}

	wg.Wait()

	for i := range clients {
		clients[i], _ = client.NewClient(i, dirAddrs, dbAddr)
		clients[i].Setup()
	}

	return dir, trustees, servers, clients, db
}

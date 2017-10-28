package trustee

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/rpc"
	"strconv"
	"strings"

	"github.com/kwonalbert/atom/directory"

	. "github.com/kwonalbert/atom/atomrpc"
	. "github.com/kwonalbert/atom/common"
	. "github.com/kwonalbert/atom/crypto"
)

type TrusteeRPC struct {
	t *Trustee
}

type Trustee struct {
	addr string
	id   int
	port int

	round     int
	roundKeys map[int]*KeyPair
	roundGood map[int]chan bool

	params     SystemParameter
	NumReports int // number of expected reports

	keyPair *KeyPair

	dirAddrs   []string
	dirServers []*rpc.Client
	directory  *directory.Directory
	publicKeys []*PublicKey

	reports map[int]chan *ReportArgs

	listener net.Listener

	tlsCert   *tls.Certificate
	tlsConfig *tls.Config

	Priv *PrivateKey
}

func NewTrustee(addr string, id int, keyFile string, dirAddrs []string) (*Trustee, error) {
	tlsCert, tlsConfig := AtomTLSConfig()

	port, err := strconv.Atoi(strings.Split(addr, ":")[1])
	if err != nil {
		log.Fatal(err)
	}

	// read key pair from a file, or generate a new key pair
	var keyPair *KeyPair
	if keyFile == "" {
		keyPair = GenKey()
	} else {
		serverKeys, err := ReadKeys(keyFile)
		if err != nil {
			return nil, err
		}
		keyPair = LoadKey(serverKeys[id])
		if err != nil {
			return nil, err
		}
	}

	l, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), tlsConfig)
	if err != nil {
		return nil, err
	}

	dirServers := make([]*rpc.Client, len(dirAddrs))
	for d, dirAddr := range dirAddrs {
		conn, err := tls.Dial("tcp", dirAddr, tlsConfig)
		if err != nil {
			return nil, err
		}
		dirServers[d] = rpc.NewClient(conn)
	}

	t := &Trustee{
		addr: addr,
		id:   id,
		port: port,

		round:     0,
		roundKeys: make(map[int]*KeyPair),
		roundGood: make(map[int]chan bool),

		keyPair: keyPair,

		dirAddrs:   dirAddrs,
		dirServers: dirServers,

		listener: l,

		reports: make(map[int]chan *ReportArgs),

		tlsCert:   tlsCert,
		tlsConfig: tlsConfig,
	}
	rpcServer := rpc.NewServer()
	rpcServer.Register(&TrusteeRPC{t})
	go rpcServer.Accept(l)
	return t, nil
}

func (t *Trustee) Setup() {
	if t.id == 0 {
		fmt.Println("Registering trustees")
	}
	t.registerTrustee()

	if t.id == 0 {
		fmt.Println("Getting directory")
	}
	t.getDirectory()
}

func (t *Trustee) returnResult(round int, res bool) {
	for i := 0; i < t.NumReports; i++ {
		t.roundGood[round] <- res
	}
}

func (t *Trustee) checkReports(round int) {
	totalTraps := make(map[int]int)
	totalMsgs := make(map[int]int)
	for i := 0; i < t.NumReports; i++ {
		report := <-t.reports[round]
		if !report.CorrectHash || !report.CorrectTraps || !report.NoDups {
			t.returnResult(round, false)
		}
		if _, ok := totalTraps[report.Uid]; !ok {
			totalTraps[report.Uid] = report.NumTraps
			totalMsgs[report.Uid] = report.NumMsgs
		}
		if totalTraps[report.Uid] != report.NumTraps ||
			totalMsgs[report.Uid] != report.NumMsgs {
			t.returnResult(round, false)
		}
	}

	sumTraps := 0
	sumMsgs := 0
	for uid := range totalTraps {
		sumTraps += totalTraps[uid]
		sumMsgs += totalMsgs[uid]
	}
	if sumTraps != sumMsgs {
		t.returnResult(round, false)
	}
	t.returnResult(round, true)
}

func (t *Trustee) Close() {
	if t.listener != nil {
		t.listener.Close()
	}
}

func (t *Trustee) registerTrustee() {
	pub := DumpPubKey(t.keyPair.Pub)
	for _, dirServer := range t.dirServers {
		reg := &directory.Registration{
			Addr:        t.addr,
			Id:          t.id,
			Key:         pub,
			Certificate: t.tlsCert.Certificate,
		}
		err := dirServer.Call("DirectoryRPC.RegisterTrustee", reg, nil)
		if err != nil {
			log.Fatal("Register err:", err)
		}
	}
}

func (t *Trustee) getDirectory() {
	// TODO:  actually check consensus
	for _, dirServer := range t.dirServers {

		var direc directory.Directory
		err := dirServer.Call("DirectoryRPC.Directory", 0, &direc)
		if err != nil {
			log.Fatal("Directory err:", err)
		}

		t.directory = &direc
		t.params = direc.SystemParameter
		t.NumReports = t.params.NumGroups * t.params.Threshold
	}

	publicKeys := make([]*PublicKey, len(t.directory.TrusteeKeys))
	for i, pub := range t.directory.TrusteeKeys {
		publicKeys[i] = LoadPubKey(pub)
	}
	t.publicKeys = publicKeys
}

func (t *Trustee) RegisterRound() {
	// TODO: actually generate per round keys and share it,
	// instead of using long-term key every round
	// currently not using threshold for trustees
	round := t.round
	t.reports[round] = make(chan *ReportArgs, t.NumReports)
	t.roundKeys[round] = t.keyPair
	t.roundGood[round] = make(chan bool, t.NumReports)
	t.Priv = t.keyPair.Priv

	roundKey := CombinePublicKeys(t.publicKeys)
	roundPub := DumpPubKey(roundKey)

	for _, dirServer := range t.dirServers {
		reg := &directory.Registration{
			Round: t.round,
			Id:    t.id,
			Key:   roundPub,
		}
		err := dirServer.Call("DirectoryRPC.RegisterRound", reg, nil)
		if err != nil {
			log.Fatal("Register err:", err)
		}
	}

	go t.checkReports(round)

	t.round += 1
}

func (t *TrusteeRPC) Report(report *ReportArgs, reply *ReportReply) error {
	t.t.reports[report.Round] <- report
	ok := <-t.t.roundGood[report.Round]
	if ok {
		*reply = ReportReply{
			Priv: t.t.keyPair.Priv,
		}
		return nil
	} else {
		return errors.New("Report failed")
	}

}

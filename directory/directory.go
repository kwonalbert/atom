package directory

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/rpc"
	"sync"
	"time"

	. "github.com/kwonalbert/atom/atomrpc"
	. "github.com/kwonalbert/atom/common"
)

type Directory struct {
	id   int
	port int

	// used to wait for server+trustee reg
	wg   *sync.WaitGroup
	done *sync.WaitGroup

	// used to wait for group reg
	gwg   *sync.WaitGroup
	gdone *sync.WaitGroup

	listener net.Listener

	tlsCert   *tls.Certificate
	tlsConfig *tls.Config

	// Exported fields; represents a logical directory
	SystemParameter
	Round int

	Servers      []string
	Keys         []string
	Certificates [][][]byte

	Trustees     []string
	TrusteeKeys  []string
	TrusteeCerts [][][]byte

	GroupKeys [][]string     // uid to group key
	RoundKeys map[int]string // round to per round key
}

type DirectoryRPC struct {
	d *Directory
}

type Registration struct {
	Round       int
	Addr        string
	Level       int // only relevant for group registration
	Id          int
	Key         string
	Certificate [][]byte
}

func (d *DirectoryRPC) Directory(_ *int, dir *Directory) error {
	d.d.wg.Wait()
	*dir = *(d.d)
	d.d.done.Done()
	return nil
}

func (d *DirectoryRPC) DirectoryWithGroupKeys(_ *int, dir *Directory) error {
	d.d.gwg.Wait()
	*dir = *(d.d)
	d.d.gdone.Done()
	return nil
}

func (d *DirectoryRPC) Register(reg *Registration, _ *int) error {
	d.d.Servers[reg.Id] = reg.Addr
	d.d.Keys[reg.Id] = reg.Key
	d.d.Certificates[reg.Id] = reg.Certificate
	d.d.wg.Done()
	return nil
}

func (d *DirectoryRPC) RegisterGroup(reg *Registration, _ *int) error {
	d.d.GroupKeys[reg.Level][reg.Id] = reg.Key
	d.d.gwg.Done()
	return nil
}

func (d *DirectoryRPC) RegisterRound(reg *Registration, _ *int) error {
	d.d.gwg.Done()
	if key, ok := d.d.RoundKeys[reg.Round]; !ok {
		d.d.RoundKeys[reg.Round] = reg.Key
		return nil
	} else {
		if key != reg.Key {
			return errors.New("Mismatching round key registration")
		} else {
			return nil
		}
	}
}

func (d *DirectoryRPC) RegisterTrustee(reg *Registration, _ *int) error {
	// TODO: Authenticate client somehow..
	d.d.Trustees[reg.Id] = reg.Addr
	d.d.TrusteeKeys[reg.Id] = reg.Key
	d.d.TrusteeCerts[reg.Id] = reg.Certificate
	d.d.wg.Done()
	return nil
}

func (d *DirectoryRPC) Ping(_ *int, _ *int) error {
	return nil
}

func (d *DirectoryRPC) Randomness(_ *int, seed *[SEED_LEN]byte) error {
	*seed = SEED
	return nil
}

func (d *Directory) Close() {
	d.done.Wait()
	d.gdone.Wait()
	// Hopefully a second is enough to send back the last reply
	time.Sleep(1 * time.Second)

	if d.listener != nil {
		d.listener.Close()
	}
}

func NewDirectory(id, port, mode, netType,
	numServers, numGroups, perGroup, numTrustees,
	numMsgs, msgSize, threshold,
	numClients int) (*Directory, error) {

	tlsCert, tlsConfig := AtomTLSConfig()

	numLevels := 10
	if netType == BUTTERFLY {
		numLevels = Log2(numGroups) * Log2(numGroups)
	}

	p := SystemParameter{
		Mode:    mode,
		NetType: netType,

		NumServers:  numServers,
		NumGroups:   numGroups,
		PerGroup:    perGroup,
		NumLevels:   numLevels,
		NumTrustees: numTrustees,

		NumMsgs: numMsgs,
		MsgSize: msgSize,

		Threshold: threshold,
	}

	l, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), tlsConfig)
	if err != nil {
		return nil, err
	}

	d := &Directory{
		id:   id,
		port: port,

		wg:   new(sync.WaitGroup),
		done: new(sync.WaitGroup),

		gwg:   new(sync.WaitGroup),
		gdone: new(sync.WaitGroup),

		listener: l,

		tlsCert:   tlsCert,
		tlsConfig: tlsConfig,

		Round:           0,
		SystemParameter: p,

		Servers:      make([]string, numServers),
		Keys:         make([]string, numServers),
		Certificates: make([][][]byte, numServers),

		Trustees:     make([]string, numTrustees),
		TrusteeKeys:  make([]string, numTrustees),
		TrusteeCerts: make([][][]byte, numTrustees),

		GroupKeys: make([][]string, numLevels),
		RoundKeys: make(map[int]string),
	}

	for level := range d.GroupKeys {
		d.GroupKeys[level] = make([]string, numGroups)
	}

	d.wg.Add(numServers + numTrustees)
	d.gwg.Add(numGroups*numLevels + numTrustees)

	d.done.Add(numServers + numTrustees)
	d.gdone.Add(numClients + numServers)

	rpcServer := rpc.NewServer()
	rpcServer.Register(&DirectoryRPC{d})
	go rpcServer.Accept(l)

	return d, nil
}

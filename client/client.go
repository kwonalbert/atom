package client

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"log"
	"net/rpc"
	"time"

	. "github.com/kwonalbert/atom/atomrpc"
	. "github.com/kwonalbert/atom/common"
	. "github.com/kwonalbert/atom/crypto"

	"github.com/kwonalbert/atom/directory"
)

type Client struct {
	id int

	params  SystemParameter
	network [][]*Group

	dirAddrs   []string
	dirServers []*rpc.Client
	dbServer   *rpc.Client
	directory  *directory.Directory
	publicKeys []*PublicKey

	start time.Time

	tlsConfig *tls.Config
}

func NewClient(id int, dirAddrs []string, dbAddr string) (*Client, error) {
	_, tlsConfig := AtomTLSConfig()

	dirServers := make([]*rpc.Client, len(dirAddrs))
	for d, dirAddr := range dirAddrs {
		conn, err := tls.Dial("tcp", dirAddr, tlsConfig)
		if err != nil {
			return nil, err
		}
		dirServers[d] = rpc.NewClient(conn)
	}

	conn, err := tls.Dial("tcp", dbAddr, tlsConfig)
	if err != nil {
		return nil, err
	}
	dbServer := rpc.NewClient(conn)

	c := &Client{
		id:         id,
		dirAddrs:   dirAddrs,
		dirServers: dirServers,
		dbServer:   dbServer,

		tlsConfig: tlsConfig,
	}

	return c, nil
}

// primary function used by clients
func (c *Client) Submit(gid, round int, plaintexts [][]byte) {
	msgs := c.generateMessages(round, plaintexts)

	// commit the traps first
	if c.params.Mode == TRAP_MODE {
		traps := c.generateTraps(c.id)
		trapMsgs := c.generateTrapMsgs(traps, len(msgs[0]))
		msgs = append(msgs, trapMsgs...)

		if c.id == 0 {
			log.Println("Committing traps")
		}
		cargs := c.generateCommitArgs(c.id, traps)
		c.commit(c.id, cargs)
	}

	submitArgs := c.generateSubmitArgs(gid, round, msgs)
	c.submit(gid, submitArgs)
	c.start = time.Now()
}

func (c *Client) Setup() {
	var keys [][]*PublicKey
	c.directory, c.params, c.publicKeys, keys = directory.GetGroupKeys(c.dirServers)

	var seed [SEED_LEN]byte
	for _, dirServer := range c.dirServers {
		var val [SEED_LEN]byte
		err := dirServer.Call("DirectoryRPC.Randomness", 0, &val)
		if err != nil {
			log.Fatal("Randomness err:", err)
		}
		Xor(val[:], seed[:])
	}
	network := GenerateGroups(seed, c.params.NetType, c.params.NumServers,
		c.params.NumGroups, c.params.PerGroup,
		c.params.NumLevels, c.publicKeys)
	c.network = network

	for level := range keys {
		for gid := range keys[level] {
			c.network[level][gid].GroupKey = keys[level][gid]
		}
	}

}

func (c *Client) GenRandPlaintexts() [][]byte {
	plaintexts := make([][]byte, c.params.NumMsgs)
	for p := range plaintexts {
		plaintexts[p] = make([]byte, c.params.MsgSize)
		rand.Read(plaintexts[p])
	}
	return plaintexts
}

func (c *Client) DownloadMsgs(round int) ([][]byte, error) {
	args := DBArgs{
		Round:     round,
		NumGroups: c.params.NumGroups,
	}
	var res [][]byte
	err := c.dbServer.Call("DB.Read", &args, &res)
	if err != nil {
		return nil, err
	}
	log.Println("Done with client", c.id, ".", time.Since(c.start), ". #msgs: ", c.params.NumMsgs)
	return res, nil
}

func (c *Client) generateRandomMsgs() []Message {
	numPts := c.params.MsgSize / PickLen()
	if c.params.MsgSize%PickLen() != 0 {
		numPts += 1
	}
	return GenRandMsgs(c.params.NumMsgs, numPts)
}

func (c *Client) generateMessages(round int, plaintexts [][]byte) []Message {
	if c.params.Mode == TRAP_MODE {
		buf := new(bytes.Buffer)
		err := binary.Write(buf, binary.LittleEndian, uint32(round))
		if err != nil {
			log.Fatal("Could not write round")
		}

		trusteeKey := LoadPubKey(c.directory.RoundKeys[round])

		inners := make([]InnerCiphertext, len(plaintexts))
		for i := range inners {
			inners[i] = CCA2Encrypt(plaintexts[i], buf.Bytes(), trusteeKey)
		}
		msgs := make([]Message, len(inners))
		for i := range inners {
			cMessage := GenMsg(inners[i].C)
			msgs[i] = append([]*Point{inners[i].R}, cMessage...)
		}
		return msgs
	} else {
		return GenMsgs(plaintexts)
	}
}

func (c *Client) generateTraps(gid int) []Trap {
	traps := make([]Trap, c.params.NumMsgs)
	for t := range traps {
		traps[t] = GenTrap(gid)
	}
	return traps
}

func (c *Client) generateTrapMsgs(traps []Trap, msgSize int) []Message {
	numPts := c.params.MsgSize / PickLen()
	if c.params.MsgSize%PickLen() != 0 {
		numPts += 1
	}

	msgs := make([]Message, c.params.NumMsgs)
	var err error
	for t := range traps {
		msgs[t], err = TrapToMessage(traps[t], numPts)
		if err != nil {
			log.Fatal("trap err:", err)
		}
	}
	return msgs
}

func (c *Client) generateSubmitArgs(gid, round int, msgs []Message) *SubmitArgs {
	group := c.network[0][gid]
	info := ArgInfo{
		Round: round,
		Level: 0,
		Gid:   gid,
		Cur:   0,
		Group: Xrange(c.params.Threshold),
	}

	ciphertexts := make([]Ciphertext, len(msgs))
	proofs := make([]EncProof, len(msgs))
	for c := range ciphertexts {
		ciphertexts[c], proofs[c] = ProveEncrypt(group.GroupKey, msgs[c])
	}

	args := SubmitArgs{
		Id:          c.id,
		Ciphertexts: ciphertexts,
		EncProofs:   proofs,
		ArgInfo:     info,
	}
	return &args
}

func (c *Client) generateCommitArgs(gid int, traps []Trap) *CommitArgs {
	info := ArgInfo{
		Round: 0,
		Level: 0,
		Gid:   gid,
		Cur:   0,
		Group: Xrange(c.params.Threshold),
	}

	comms := make([]Commitment, len(traps))
	for t := range traps {
		comms[t] = Commit(traps[t])
	}

	args := CommitArgs{
		Id:      c.id,
		Comms:   comms,
		ArgInfo: info,
	}
	return &args
}

func (c *Client) submit(gid int, args *SubmitArgs) {
	group := c.network[0][gid]
	for _, idx := range args.Group {
		addr := c.directory.Servers[group.Members[idx]]
		conn, err := tls.Dial("tcp", addr, c.tlsConfig)
		if err != nil {
			log.Fatal(err)
		}
		server := rpc.NewClient(conn)
		if err != nil {
			log.Fatal(err)
		}
		err = AtomRPC(server, "ServerRPC.Submit", args, nil, DEFAULT_TIMEOUT)
		if err != nil {
			log.Fatal(err)
		}
		server.Close()
	}
}

func (c *Client) commit(gid int, args *CommitArgs) {
	group := c.network[0][gid]

	for _, idx := range args.Group {
		addr := c.directory.Servers[group.Members[idx]]
		conn, err := tls.Dial("tcp", addr, c.tlsConfig)
		if err != nil {
			log.Fatal(err)
		}
		server := rpc.NewClient(conn)
		if err != nil {
			log.Fatal(err)
		}
		err = AtomRPC(server, "ServerRPC.Commit", args, nil, DEFAULT_TIMEOUT)
		if err != nil {
			log.Fatal(err)
		}
		server.Close()
	}
}

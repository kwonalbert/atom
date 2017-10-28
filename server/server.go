package server

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/rpc"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kwonalbert/atom/directory"

	. "github.com/kwonalbert/atom/atomrpc"
	. "github.com/kwonalbert/atom/common"
	. "github.com/kwonalbert/atom/crypto"
)

type ServerRPC struct {
	s *Server
}

type Server struct {
	id   int
	addr string
	port int

	params SystemParameter

	dirAddrs   []string
	dirServers []*rpc.Client
	dbServer   *rpc.Client
	servers    []*rpc.Client
	directory  *directory.Directory
	publicKeys []*PublicKey

	trustees []*rpc.Client

	network [][]*Group
	partOf  [][]*Group
	members map[int]*Member // maps a unique group id (not gid) to a member

	keyPair   *KeyPair
	connected *sync.WaitGroup

	listener net.Listener

	tlsCert   *tls.Certificate
	tlsConfig *tls.Config

	start time.Time
	slock *sync.Mutex
}

func NewServer(addr string, id int, keyFile string,
	dirAddrs []string, dbAddr string) (*Server, error) {
	port, err := strconv.Atoi(strings.Split(addr, ":")[1])
	if err != nil {
		log.Fatal(err)
	}

	tlsCert, tlsConfig := AtomTLSConfig()

	if id == 0 {
		fmt.Println("Server started")
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
	}

	dirServers := make([]*rpc.Client, len(dirAddrs))
	for d, dirAddr := range dirAddrs {
		conn, err := tls.Dial("tcp", dirAddr, tlsConfig)
		if err != nil {
			return nil, err
		}
		dirServers[d] = rpc.NewClient(conn)
		var tmp int
		err = dirServers[d].Call("DirectoryRPC.Ping", &tmp, &tmp)
		if err != nil {
			return nil, err
		}
	}

	conn, err := tls.Dial("tcp", dbAddr, tlsConfig)
	if err != nil {
		return nil, err
	}
	dbServer := rpc.NewClient(conn)

	connected := new(sync.WaitGroup)
	connected.Add(1)

	s := &Server{
		id:   id,
		addr: addr,
		port: port,

		dirAddrs:   dirAddrs,
		dbServer:   dbServer,
		dirServers: dirServers,

		keyPair: keyPair,

		connected: connected,

		tlsCert:   tlsCert,
		tlsConfig: tlsConfig,

		slock: new(sync.Mutex),
	}

	return s, nil
}

func (s *Server) Setup() {
	s.registerServer()
	if s.id == 0 {
		log.Println("Registered server")
	}

	s.getDirectory()
	if s.id == 0 {
		log.Println("Got directory")
	}

	s.accept()
	if s.id == 0 {
		log.Println("Server started")
	}

	s.connectServers()
	if s.id == 0 {
		log.Println("Connected servers")
	}

	s.genMemberKeys()
	if s.id == 0 {
		log.Println("Generated member key")
	}

	s.setupGroupKeys()
	if s.id == 0 {
		log.Println("Generated group key")
	}
}

func (s *Server) Close() {
	if s.listener != nil {
		s.listener.Close()
	}

	for _, dirServer := range s.dirServers {
		dirServer.Close()
	}

	for _, serv := range s.servers {
		if serv != nil {
			serv.Close()
		}
	}
}

func (s *Server) accept() {
	l, e := tls.Listen("tcp", fmt.Sprintf(":%d", s.port), s.tlsConfig)
	if e != nil {
		log.Fatal("listen error:", e)
	}
	s.listener = l

	rpcServer := rpc.NewServer()
	rpcServer.Register(&ServerRPC{s})
	go rpcServer.Accept(l)
}

func (s *Server) registerServer() {
	pub := DumpPubKey(s.keyPair.Pub)
	for _, dirServer := range s.dirServers {
		reg := &directory.Registration{
			Addr:        s.addr,
			Id:          s.id,
			Key:         pub,
			Certificate: s.tlsCert.Certificate,
		}
		err := dirServer.Call("DirectoryRPC.Register", reg, nil)
		if err != nil {
			log.Fatal("Register err:", err)
		}
	}
}

func (s *Server) getDirectory() {
	s.directory, s.params, s.publicKeys = directory.GetDirectory(s.dirServers)
	if s.params.Mode == TRAP_MODE {
		s.trustees = make([]*rpc.Client, len(s.directory.Trustees))
		for t, tAddr := range s.directory.Trustees {
			conn, err := tls.Dial("tcp", tAddr, s.tlsConfig)
			if err != nil {
				log.Fatal("Could not dial trustee")
			}
			s.trustees[t] = rpc.NewClient(conn)
		}
	}
	s.genGroups()
}

func (s *Server) genGroups() {
	var seed [SEED_LEN]byte
	for _, dirServer := range s.dirServers {
		var val [SEED_LEN]byte
		err := dirServer.Call("DirectoryRPC.Randomness", 0, &val)
		if err != nil {
			log.Fatal("Randomness err:", err)
		}
		Xor(val[:], seed[:])
	}
	network := GenerateGroups(seed, s.params.NetType, s.params.NumServers,
		s.params.NumGroups, s.params.PerGroup,
		s.params.NumLevels, s.publicKeys)
	s.network = network

	s.partOf = make([][]*Group, len(network))
	s.members = make(map[int]*Member)
	for level := range s.partOf {
		s.partOf[level] = make([]*Group, len(network[level]))
		for gid, node := range network[level] {
			if !IsMember(s.id, node.Members) {
				s.partOf[level][gid] = nil
				continue
			}
			group := network[level][gid]
			s.partOf[level][gid] = group
			s.members[group.Uid] = NewMember(s.id, s.keyPair,
				s.params, group)
		}
	}
}

func (s *Server) callGroup(servers []*rpc.Client, group *Group) []*rpc.Client {
	// connect to everyone in this group
	for _, member := range group.Members {
		if servers[member] != nil {
			continue
		}

		// all servers must be online during inital seup, so retry
		retry := 1
		for retry != 0 {
			conn, err := tls.Dial("tcp", s.directory.Servers[member], s.tlsConfig)
			if err == nil {
				retry = 0
				servers[member] = rpc.NewClient(conn)
			}
		}
	}
	return servers
}

func (s *Server) connectServers() {
	servers := make([]*rpc.Client, s.params.NumServers)
	for level := range s.partOf {
		for _, group := range s.partOf[level] {
			if group == nil {
				continue
			}
			s.callGroup(servers, group)

			// connect to all servers in neighboring group
			for _, neighbor := range group.AdjList {
				s.callGroup(servers, neighbor)
			}
		}
	}

	for _, group := range s.network[len(s.network)-1] {
		s.callGroup(servers, group)
	}

	s.servers = servers
	s.connected.Done()
}

func (s *Server) genMemberKeys() {
	if s.params.Threshold < s.params.PerGroup {
		for _, member := range s.members {
			for gidx, other := range member.group.Members {
				if member.sid == other {
					continue
				}

				//TODO: This used to be done in parallel,
				// but when moved to kyber, the encoding
				// seems to not work with RPC calls, so
				// now it's sequential..
				args := DealArgs{
					Uid:  member.group.Uid,
					Idx:  member.idx,
					Deal: member.share.GetDeal(gidx),
				}

				var reply DealReply
				err := s.servers[other].Call("ServerRPC.Deal", &args, &reply)
				if err != nil {
					log.Fatal("Deal fail:", err)
				}
			}
		}
	}

	for _, member := range s.members {
		member.genMemberKey()
	}
}

func (s *Server) addDealSendResponse(args *DealArgs) {
	s.connected.Wait()

	member := s.members[args.Uid]
	resp, err := member.share.AddDeal(args.Deal)
	if err != nil {
		log.Fatal("failed to add deal:")
	}

	for _, other := range member.group.Members {
		if member.sid == other {
			continue
		}
		args := ResponseArgs{
			Uid:  member.group.Uid,
			Resp: resp,
		}

		var reply ResponseReply
		err := s.servers[other].Call("ServerRPC.Response", &args, &reply)
		if err != nil {
			log.Fatal("Deal fail:", err)
		}
	}

}

func (s *Server) setupGroupKeys() {
	for level := range s.partOf {
		for gid := range s.partOf[level] {
			group := s.partOf[level][gid]
			if group == nil {
				continue
			}

			if group.Members[0] != s.id {
				// currently trusting the first server
				continue
			}

			pub := DumpPubKey(group.GroupKey)
			for _, dirServer := range s.dirServers {
				reg := &directory.Registration{
					Level: group.Level,
					Id:    group.Gid,
					Key:   pub,
				}
				err := dirServer.Call("DirectoryRPC.RegisterGroup", reg, nil)
				if err != nil {
					log.Fatal("Register err:", err)
				}
			}
		}
	}

	var keys [][]*PublicKey
	s.directory, s.params, _, keys = directory.GetGroupKeys(s.dirServers)
	for level := range keys {
		for gid := range keys[level] {
			s.network[level][gid].GroupKey = keys[level][gid]
		}
	}
}

func (s *Server) collect(args *CollectArgs) {
	uid := s.partOf[args.Level][args.Gid].Uid
	member := s.members[uid]

	newArgs := &ShuffleArgs{
		Ciphertexts: member.ciphertexts(args.Round),
		ArgInfo:     args.ArgInfo,
	}

	// entry groups need to wait for commitments too
	if s.params.Mode == TRAP_MODE && args.Level == 0 {
		member.commitWait(args.Round)
	}

	if args.Cur == member.idx {
		go s.shuffle(newArgs)
	}
}

func (s *Server) shuffle(args *ShuffleArgs) {
	if args.ArgInfo.Gid == 0 { // just print the first level
		log.Println("shuffle:", args.ArgInfo)
	}

	uid := s.partOf[args.Level][args.Gid].Uid
	member := s.members[uid]

	// for NIZK mode, any server other than the first
	// should collect ok from other servers
	if s.params.Mode == VER_MODE && args.Cur != args.Group[0] {
		for i := 0; i < len(args.Group)-2; i++ {
			ok := member.dequeShufOK(args.Round)
			if !ok {
				log.Fatal("Bad shuffle proof given")
			}
		}
	}

	var res []Ciphertext
	var proof ShufProof
	if s.params.Mode == TRAP_MODE {
		res = member.shuffle(args.Ciphertexts)
	} else if s.params.Mode == VER_MODE {
		res, proof = member.proveShuffle(args.Ciphertexts)
	}

	last := args.Group[len(args.Group)-1] == member.idx

	info := ArgInfo{
		Round: args.Round,
		Level: args.Level,
		Gid:   args.Gid,
		Group: args.Group,
	}

	if s.params.Mode == VER_MODE {
		// ask all other servers to verify
		for _, idx := range args.Group {
			if idx == args.Cur {
				continue
			}
			info.Cur = args.ArgInfo.Cur
			newArgs := VerifyShuffleArgs{
				Old:     args.Ciphertexts,
				New:     res,
				Proof:   proof,
				ArgInfo: info,
			}

			next := member.group.Members[idx]
			var reply ShuffleReply
			err := AtomRPC(s.servers[next], "ServerRPC.VerifyShuffle",
				&newArgs, &reply, DEFAULT_TIMEOUT)
			if err != nil {
				log.Fatal("Verify shuffle request:", err)
			}
		}
	}

	if !last { // shuffle and send to next server
		idx := -1
		for i := range args.Group {
			if args.Group[i] == member.idx {
				idx = i
				break
			}
		}
		nextIdx := args.Group[(idx+1)%len(args.Group)]
		next := member.group.Members[nextIdx]
		info.Cur = nextIdx
		newArgs := ShuffleArgs{
			Ciphertexts: res,
			ArgInfo:     info,
		}

		var reply ShuffleReply
		err := AtomRPC(s.servers[next], "ServerRPC.Shuffle",
			&newArgs, &reply, DEFAULT_TIMEOUT)
		if err != nil {
			log.Fatal("Shuffle request:", err)
		}
	} else { // divide and send back to first server
		nextIdx := args.Group[0]
		next := member.group.Members[nextIdx]
		info.Cur = nextIdx
		batches := member.divide(res)
		newArgs := ReencryptArgs{
			Batches: batches,
			ArgInfo: info,
		}

		var reply ReencryptReply
		err := AtomRPC(s.servers[next], "ServerRPC.Reencrypt",
			&newArgs, &reply, DEFAULT_TIMEOUT)
		if err != nil {
			log.Fatal("Reencrypt request:", err)
		}
	}
}

func (s *Server) verifyShuffle(args *VerifyShuffleArgs) {
	uid := s.partOf[args.Level][args.Gid].Uid
	member := s.members[uid]

	// TODO: also check args.Old == currently collected
	ok := member.verifyShuffle(args.Old, args.New, args.Proof)

	idx := -1
	for i := range args.Group {
		if args.Group[i] == args.Cur {
			idx = i
			break
		}
	}

	nextIdx := args.Group[(idx+1)%len(args.Group)]
	next := member.group.Members[nextIdx]

	if nextIdx == member.idx {
		if ok {
			return
		} else {
			log.Fatal("Bad shuffle proof")
		}
	}

	newArgs := ProofOKArgs{
		OK:      ok,
		ArgInfo: args.ArgInfo,
	}
	var reply ProofOKReply
	err := AtomRPC(s.servers[next], "ServerRPC.ShuffleOK",
		&newArgs, &reply, DEFAULT_TIMEOUT)
	if err != nil {
		log.Fatal("Shuffle ok request:", err)
	}
}

func (s *Server) reencrypt(args *ReencryptArgs) {
	if args.ArgInfo.Gid == 0 { // just print the first level
		log.Println("reencrypt:", args.ArgInfo)
	}

	uid := s.partOf[args.Level][args.Gid].Uid
	member := s.members[uid]

	priv := s.keyPair.Priv
	if member.share != nil {
		priv = member.share.Lagrange(args.Group)
	}

	if s.params.Mode == VER_MODE && args.Cur != args.Group[0] {
		for i := 0; i < len(args.Group)-2; i++ {
			ok := member.dequeReencOK(args.Round)
			if !ok {
				log.Fatal("Bad shuffle proof given")
			}
		}
	}

	var res [][]Ciphertext
	var proof [][]ReencProof
	if s.params.Mode == TRAP_MODE {
		res = member.reencrypt(args.Round, priv, args.Batches)
	} else if s.params.Mode == VER_MODE {
		res, proof = member.proveReencrypt(args.Round, priv, args.Batches)
	}

	last := args.Group[len(args.Group)-1] == member.idx

	idx := -1
	for i := range args.Group {
		if args.Group[i] == member.idx {
			idx = i
			break
		}
	}
	nextIdx := args.Group[(idx+1)%len(args.Group)]
	next := member.group.Members[nextIdx]

	info := ArgInfo{
		Round: args.Round,
		Level: args.Level,
		Gid:   args.Gid,
		Cur:   nextIdx,
		Group: args.Group,
	}

	if s.params.Mode == VER_MODE {
		// ask all other servers to verify
		for _, idx := range args.Group {
			if idx == args.Cur {
				continue
			}
			info.Cur = args.ArgInfo.Cur
			newArgs := VerifyReencryptArgs{
				Old:     args.Batches,
				New:     res,
				Proofs:  proof,
				ArgInfo: info,
			}

			next := member.group.Members[idx]
			var reply ShuffleReply
			err := AtomRPC(s.servers[next], "ServerRPC.VerifyReencrypt",
				&newArgs, &reply, DEFAULT_TIMEOUT)
			if err != nil {
				log.Fatal("Verify reencrypt request:", err)
			}
		}
	}

	if !last { // reencrypt and send to next server
		newArgs := ReencryptArgs{
			Batches: res,
			ArgInfo: info,
		}

		var reply ShuffleReply
		err := AtomRPC(s.servers[next], "ServerRPC.Reencrypt",
			&newArgs, &reply, DEFAULT_TIMEOUT)
		if err != nil {
			log.Fatal(err)
		}
	} else if args.Level == s.params.NumLevels-1 { // last level
		// FINISH PROTOCOL
		msgs := ExtractMessages(res[0])
		if s.params.Mode == VER_MODE {
			plaintexts, _, err := ExtractPlaintexts(msgs)
			if err != nil {
				log.Fatal(err)
			}

			info := ArgInfo{
				Round: args.Round,
				Level: args.Level,
				Gid:   args.Gid,
				Group: args.Group,
			}
			newArgs := FinalizeArgs{
				Plaintexts: plaintexts,
				ArgInfo:    info,
			}
			for _, other := range member.group.Members {
				var reply FinalizeReply
				err := AtomRPC(s.servers[other], "ServerRPC.Finalize",
					&newArgs, &reply, DEFAULT_TIMEOUT)
				if err != nil {
					log.Fatal(err)
				}
			}
		} else {
			inners, traps, err := ExtractInnerAndTraps(msgs)
			if err != nil {
				log.Fatal(err)
			}

			innerDivs := make([][]InnerCiphertext, s.params.NumGroups)
			for i := range inners {
				gid := selectGroup(inners[i], s.params.NumGroups)
				innerDivs[gid] = append(innerDivs[gid], inners[i])
			}

			trapDivs := make([][]Trap, s.params.NumGroups)
			for t := range traps {
				gid := traps[t].Gid
				trapDivs[gid] = append(trapDivs[gid], traps[t])
			}

			// the first layer servers are responsible for verifying
			// since they know the commitments
			for _, group := range s.network[0] {
				info := ArgInfo{
					Round: args.Round,
					Level: 0,
					Gid:   group.Gid,
					Group: args.Group,
				}

				newArgs := FinalizeArgs{
					Inners:  innerDivs[group.Gid],
					Traps:   trapDivs[group.Gid],
					ArgInfo: info,
				}
				for _, idx := range args.Group {
					other := group.Members[idx]
					var reply FinalizeReply
					err := AtomRPC(s.servers[other], "ServerRPC.Finalize",
						&newArgs, &reply, DEFAULT_TIMEOUT)
					if err != nil {
						log.Fatal(err)
					}
				}

			}
		}
	} else { // send to neighbors
		for n, neighbor := range member.group.AdjList {
			info := ArgInfo{
				Round: args.Round,
				Level: args.Level + 1,
				Gid:   neighbor.Gid,
				Cur:   0,
				Group: Xrange(s.params.Threshold),
			}

			for r := range res[n] { // no need for Y any more
				res[n][r].Y = nil
			}

			for _, idx := range info.Group {
				if s.params.Mode == TRAP_MODE && idx != info.Cur {
					continue
				}
				newArgs := CollectArgs{
					Id:          member.group.Gid,
					Ciphertexts: res[n],
					ArgInfo:     info,
				}

				next := neighbor.Members[idx]

				var reply ReencryptReply
				err := AtomRPC(s.servers[next], "ServerRPC.Collect",
					&newArgs, &reply, DEFAULT_TIMEOUT)
				if err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}

func (s *Server) verifyReencrypt(args *VerifyReencryptArgs) {
	uid := s.partOf[args.Level][args.Gid].Uid
	member := s.members[uid]

	// also check args.Old == currently collected
	ok := member.verifyReencrypt(args.Old, args.New, args.Proofs)

	idx := -1
	for i := range args.Group {
		if args.Group[i] == member.idx {
			idx = i
			break
		}
	}
	nextIdx := args.Group[(idx+1)%len(args.Group)]
	next := member.group.Members[nextIdx]

	newArgs := ProofOKArgs{
		OK:      ok,
		ArgInfo: args.ArgInfo,
	}
	var reply ProofOKReply
	err := AtomRPC(s.servers[next], "ServerRPC.ReencryptOK",
		&newArgs, &reply, DEFAULT_TIMEOUT)
	if err != nil {
		log.Fatal(err)
	}
}

func (s *Server) finalize(args *FinalizeArgs) {
	if args.ArgInfo.Gid == 0 { // just print the first level
		log.Println("finalize:", args.ArgInfo)
	}

	uid := s.partOf[args.Level][args.Gid].Uid
	member := s.members[uid]
	last := args.Group[len(args.Group)-1] == member.idx

	if s.params.Mode == VER_MODE {
		if last {
			args := DBArgs{
				Round:     args.Round,
				NumGroups: s.params.NumGroups,
				Msgs:      args.Plaintexts,
			}
			err := s.dbServer.Call("DB.Write", args, nil)
			if err != nil {
				log.Fatal("DB Write error:", err)
			}
		}
		if member.idx == args.Group[0] {
			log.Println("Done with group", member.group.Gid, ":", time.Since(s.start), ". #msgs: ", s.params.NumMsgs)
		}
		return
	}

	// everything below is for trap mode only
	inners, traps := member.results(args.Round)

	// check that each inner msg is expected to be here
	// and there are no duplicates
	dups := make(map[string]bool)
	noDups := true
	correctHash := true
	for i := range inners {
		gid := selectGroup(inners[i], s.params.NumGroups)
		correctHash = correctHash && (gid == member.group.Gid)

		str := string(inners[i].C)
		if _, ok := dups[str]; !ok {
			dups[str] = true
		} else {
			noDups = false
		}
	}

	// check all traps are there
	comms := make([]Commitment, len(traps))
	for t := range traps {
		comms[t] = Commit(traps[t])
	}
	expComms := member.commitments(args.Round)
	correctTraps := len(expComms) == len(comms)
	for _, comm := range expComms {
		correctTraps = correctTraps && memberCommitment(comm, comms)
	}

	// report to all trustees
	newArgs := ReportArgs{
		Round:        args.Round,
		Sid:          s.id,
		Uid:          uid,
		CorrectHash:  correctHash,
		CorrectTraps: correctTraps,
		NoDups:       noDups,
		NumTraps:     len(traps),
		NumMsgs:      len(inners),
	}

	privs := make([]*PrivateKey, len(s.trustees))
	for t, trustee := range s.trustees {
		var reply ReportReply
		err := trustee.Call("TrusteeRPC.Report", &newArgs, &reply)
		if err != nil {
			log.Fatal("Could not get keys from trustee:", err)
		}
		privs[t] = reply.Priv
	}
	priv := CombinePrivateKeys(privs)
	pub := LoadPubKey(s.directory.RoundKeys[args.Round])

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, uint32(args.Round))
	if err != nil {
		log.Fatal("Could not write round")
	}
	nonce := buf.Bytes()

	plaintexts := make([][]byte, len(inners))
	for i := range inners {
		plaintexts[i], err = CCA2Decrypt(inners[i], nonce, priv, pub)
		if err != nil {
			log.Fatal("CCA2 Decrypt fail:", err)
		}
	}

	dbArgs := DBArgs{
		Round:     args.Round,
		NumGroups: s.params.NumGroups,
		Msgs:      plaintexts,
	}
	err = s.dbServer.Call("DB.Write", dbArgs, nil)
	if err != nil {
		log.Fatal("DB Write error:", err)
	}

	if member.idx == args.Group[0] {
		log.Println("Done with group", member.group.Gid, ":", time.Since(s.start), ". #msgs: ", s.params.NumMsgs)
	}
}

func (s *ServerRPC) Deal(args *DealArgs, _ *DealReply) error {
	go s.s.addDealSendResponse(args)
	return nil
}

func (s *ServerRPC) Response(args *ResponseArgs, _ *ResponseReply) error {
	member := s.s.members[args.Uid]
	return member.share.AddResponse(args.Resp)
}

func (s *ServerRPC) Submit(args *SubmitArgs, _ *SubmitReply) error {
	if args.Level == 0 {
		s.s.slock.Lock()
		s.s.start = time.Now()
		s.s.slock.Unlock()
	}

	uid := s.s.partOf[args.Level][args.Gid].Uid
	member := s.s.members[uid]

	for c := range args.Ciphertexts {
		err := VerifyEncrypt(member.group.GroupKey,
			args.Ciphertexts[c], args.EncProofs[c])
		if err != nil {
			return err
		}
	}

	if s.s.params.Mode == TRAP_MODE && member.idx != args.Cur {
		// TODO: send the verification result to all servers
		return nil
	}

	started := member.roundStarted(args.Round)
	if !started {
		member.startRound(args.Round)
		newArgs := &CollectArgs{
			Id:          args.Id,
			Ciphertexts: args.Ciphertexts,
			ArgInfo:     args.ArgInfo,
		}
		go s.s.collect(newArgs)
	}

	member.collect(args.Round, args.Id, args.Ciphertexts)
	return nil
}

func (s *ServerRPC) Commit(args *CommitArgs, _ *CommitReply) error {
	uid := s.s.partOf[args.Level][args.Gid].Uid
	member := s.s.members[uid]

	started := member.roundStarted(args.Round)
	if !started {
		member.startRound(args.Round)
		newArgs := &CollectArgs{
			Id:      args.Id,
			ArgInfo: args.ArgInfo,
		}
		go s.s.collect(newArgs)
	}

	member.collectCommitment(args.Round, args.Id, args.Comms)
	return nil
}

func (s *ServerRPC) Collect(args *CollectArgs, _ *CollectReply) error {
	uid := s.s.partOf[args.Level][args.Gid].Uid
	member := s.s.members[uid]

	started := member.roundStarted(args.Round)
	if !started {
		member.startRound(args.Round)
		go s.s.collect(args)
	}
	member.collect(args.Round, args.Id, args.Ciphertexts)
	return nil
}

func (s *ServerRPC) Shuffle(args *ShuffleArgs, _ *ShuffleReply) error {
	go s.s.shuffle(args)
	return nil
}

func (s *ServerRPC) VerifyShuffle(args *VerifyShuffleArgs, _ *VerifyShuffleReply) error {
	go s.s.verifyShuffle(args)
	return nil
}

func (s *ServerRPC) ShuffleOK(args *ProofOKArgs, _ *ProofOKReply) error {
	uid := s.s.partOf[args.Level][args.Gid].Uid
	member := s.s.members[uid]
	// TODO: actually check if the person sending this is the right server
	member.queueShufOK(args.Round, args.OK)
	return nil
}

func (s *ServerRPC) Reencrypt(args *ReencryptArgs, _ *ReencryptReply) error {
	go s.s.reencrypt(args)
	return nil
}

func (s *ServerRPC) VerifyReencrypt(args *VerifyReencryptArgs, _ *VerifyReencryptReply) error {
	go s.s.verifyReencrypt(args)
	return nil
}

func (s *ServerRPC) ReencryptOK(args *ProofOKArgs, _ *ProofOKReply) error {
	uid := s.s.partOf[args.Level][args.Gid].Uid
	member := s.s.members[uid]
	// TODO: actually check if the person sending this is the right server
	member.queueReencOK(args.Round, args.OK)
	return nil
}

func (s *ServerRPC) Finalize(args *FinalizeArgs, _ *FinalizeReply) error {
	uid := s.s.partOf[args.Level][args.Gid].Uid
	member := s.s.members[uid]

	if s.s.params.Mode == TRAP_MODE {
		started := member.finalizeStarted(args.Round)
		if !started {
			member.startFinalize(args.Round)
			go s.s.finalize(args)
		}
		member.collectResult(args.Round, args.Inners, args.Traps)
	} else {
		go s.s.finalize(args)
	}
	return nil
}

func (s *ServerRPC) Ping(_ *int, _ *int) error {
	return nil
}

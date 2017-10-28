package server

import (
	"log"
	"sync"

	. "github.com/kwonalbert/atom/common"
	atomcrypto "github.com/kwonalbert/atom/crypto"
)

// Member of a group
type Member struct {
	sid   int // server id
	idx   int // index in the group
	group *Group

	params SystemParameter

	share *atomcrypto.Threshold // threshold share

	roundLock *sync.Mutex
	roundInit map[int]bool

	finalizeLock *sync.Mutex

	collectBuf  map[int][]atomcrypto.Ciphertext
	collectLock map[int]*sync.Cond

	commitBuf  map[int][]atomcrypto.Commitment
	commitLock map[int]*sync.Cond

	resInnerBuf map[int]chan []atomcrypto.InnerCiphertext
	resTrapBuf  map[int]chan []atomcrypto.Trap

	shufOK  map[int]chan bool
	reencOK map[int]chan bool

	shufOld  map[int][]atomcrypto.Ciphertext
	reencOld map[int][][]atomcrypto.Ciphertext
}

func NewMember(sid int, key *atomcrypto.KeyPair, params SystemParameter, group *Group) *Member {
	groupSize := len(group.Members)
	useThreshold := params.Threshold < groupSize

	idx := -1
	for i := range group.Members {
		if group.Members[i] == sid {
			idx = i
			break
		}
	}

	var share *atomcrypto.Threshold = nil
	if useThreshold {
		share = atomcrypto.NewThreshold(idx, params.Threshold,
			key, group.MemberKeys)
	}

	m := &Member{
		sid:   sid,
		idx:   idx,
		group: group,

		params: params,

		share: share,

		roundLock:    new(sync.Mutex),
		roundInit:    make(map[int]bool),
		finalizeLock: new(sync.Mutex),

		collectBuf:  make(map[int][]atomcrypto.Ciphertext),
		collectLock: make(map[int]*sync.Cond),

		commitBuf:  make(map[int][]atomcrypto.Commitment),
		commitLock: make(map[int]*sync.Cond),

		resInnerBuf: make(map[int]chan []atomcrypto.InnerCiphertext),
		resTrapBuf:  make(map[int]chan []atomcrypto.Trap),

		shufOK:  make(map[int]chan bool),
		reencOK: make(map[int]chan bool),

		shufOld:  make(map[int][]atomcrypto.Ciphertext),
		reencOld: make(map[int][][]atomcrypto.Ciphertext),
	}
	return m
}

func (m *Member) genMemberKey() {
	var groupKey *atomcrypto.PublicKey = nil
	if m.share != nil {
		m.share.JVSS()
		groupKey = m.share.PublicKey()
	} else {
		groupKey = atomcrypto.CombinePublicKeys(m.group.MemberKeys)
	}
	m.group.GroupKey = groupKey
}

func (m *Member) ciphertexts(round int) []atomcrypto.Ciphertext {
	if m.params.Mode == TRAP_MODE {
		m.collectLock[round].L.Lock()
		for len(m.collectBuf[round]) < 2*m.params.NumMsgs {
			m.collectLock[round].Wait()
		}
		m.collectLock[round].L.Unlock()
	} else {
		m.collectLock[round].L.Lock()
		for len(m.collectBuf[round]) < m.params.NumMsgs {
			m.collectLock[round].Wait()
		}
		m.collectLock[round].L.Unlock()
	}
	return m.collectBuf[round]
}

func (m *Member) commitWait(round int) {
	m.commitLock[round].L.Lock()
	for len(m.commitBuf[round]) < m.params.NumMsgs {
		m.commitLock[round].Wait()
	}
	m.commitLock[round].L.Unlock()
}

func (m *Member) startRound(round int) {
	if m.roundStarted(round) {
		return
	}
	m.roundLock.Lock()
	defer m.roundLock.Unlock()

	m.roundInit[round] = true
	m.collectBuf[round] = nil
	m.collectLock[round] = sync.NewCond(new(sync.Mutex))
	m.commitLock[round] = sync.NewCond(new(sync.Mutex))
	if m.params.Mode == TRAP_MODE {
		m.commitBuf[round] = nil
	} else {
		m.shufOK[round] = make(chan bool, m.params.Threshold)
		m.reencOK[round] = make(chan bool, m.params.Threshold)
	}
}

func (m *Member) roundStarted(round int) bool {
	m.roundLock.Lock()
	defer m.roundLock.Unlock()
	_, ok := m.roundInit[round]
	return ok
}

func (m *Member) collect(round int, id int, ciphertexts []atomcrypto.Ciphertext) {
	m.collectLock[round].L.Lock()
	m.collectBuf[round] = append(m.collectBuf[round], ciphertexts...)
	m.collectLock[round].Signal()
	m.collectLock[round].L.Unlock()
}

func (m *Member) collectCommitment(round int, id int, comms []atomcrypto.Commitment) {
	m.commitLock[round].L.Lock()
	m.commitBuf[round] = append(m.commitBuf[round], comms...)
	m.commitLock[round].Signal()
	m.commitLock[round].L.Unlock()
}

func (m *Member) verifyShuffle(old, new []atomcrypto.Ciphertext, proof atomcrypto.ShufProof) bool {
	err := atomcrypto.VerifyShuffle(m.group.GroupKey, old, new, proof)
	if err != nil {
		log.Println("Incorrect shuffle proof:", err)
		return false
	}
	return true
}

func (m *Member) queueShufOK(round int, ok bool) {
	m.shufOK[round] <- ok
}

func (m *Member) dequeShufOK(round int) bool {
	ok := <-m.shufOK[round]
	return ok
}

func (m *Member) shuffle(ciphertexts []atomcrypto.Ciphertext) []atomcrypto.Ciphertext {
	return atomcrypto.Shuffle(m.group.GroupKey, ciphertexts)
}

func (m *Member) proveShuffle(ciphertexts []atomcrypto.Ciphertext) ([]atomcrypto.Ciphertext, atomcrypto.ShufProof) {
	return atomcrypto.ProveShuffle(m.group.GroupKey, ciphertexts)
}

func (m *Member) divide(cs []atomcrypto.Ciphertext) [][]atomcrypto.Ciphertext {
	numNeighbors := len(m.group.AdjList)
	if numNeighbors == 0 {
		numNeighbors = 1 // last level, there are no neighbors
	}
	batches := make([][]atomcrypto.Ciphertext, numNeighbors)
	// TODO: assumes even sized batches; make it more general
	batchSize := len(cs) / numNeighbors
	for b := range batches {
		batches[b] = cs[b*batchSize : (b+1)*batchSize]
	}
	return batches
}

func (m *Member) neighborKeys(n int) []*atomcrypto.PublicKey {
	neighborKeys := make([]*atomcrypto.PublicKey, n)
	if len(m.group.AdjList) > 0 { // special case for last level
		for n, neighbor := range m.group.AdjList {
			neighborKeys[n] = neighbor.GroupKey
		}
	} else {
		neighborKeys[0] = atomcrypto.NullKey()
	}
	return neighborKeys
}

func (m *Member) verifyReencrypt(ob, nb [][]atomcrypto.Ciphertext, proofs [][]atomcrypto.ReencProof) bool {
	return atomcrypto.VerifyReencryptBatches(ob, nb,
		proofs, m.neighborKeys(len(nb)))
}

func (m *Member) queueReencOK(round int, ok bool) {
	m.reencOK[round] <- ok
}

func (m *Member) dequeReencOK(round int) bool {
	ok := <-m.reencOK[round]
	return ok
}

// decrypt using priv and reencrypt the message for neighbors
func (m *Member) reencrypt(round int, priv *atomcrypto.PrivateKey,
	batches [][]atomcrypto.Ciphertext) [][]atomcrypto.Ciphertext {
	return atomcrypto.ReencryptBatches(priv, m.neighborKeys(len(batches)), batches)
}

// decrypt using priv and reencrypt the message for neighbors
func (m *Member) proveReencrypt(round int, priv *atomcrypto.PrivateKey,
	batches [][]atomcrypto.Ciphertext) ([][]atomcrypto.Ciphertext, [][]atomcrypto.ReencProof) {
	return atomcrypto.ProveReencryptBatches(priv, m.neighborKeys(len(batches)), batches)
}

func (m *Member) startFinalize(round int) {
	m.finalizeLock.Lock()
	defer m.finalizeLock.Unlock()
	m.resInnerBuf[round] = make(chan []atomcrypto.InnerCiphertext, m.params.NumGroups)
	m.resTrapBuf[round] = make(chan []atomcrypto.Trap, m.params.NumGroups)
}

func (m *Member) finalizeStarted(round int) bool {
	m.finalizeLock.Lock()
	defer m.finalizeLock.Unlock()
	_, ok := m.resInnerBuf[round]
	return ok
}

func (m *Member) collectResult(round int, inners []atomcrypto.InnerCiphertext, traps []atomcrypto.Trap) {
	m.resInnerBuf[round] <- inners
	m.resTrapBuf[round] <- traps
}

func (m *Member) results(round int) ([]atomcrypto.InnerCiphertext, []atomcrypto.Trap) {
	var inners []atomcrypto.InnerCiphertext
	var traps []atomcrypto.Trap

	for i := 0; i < m.params.NumGroups; i++ {
		tmpi := <-m.resInnerBuf[round]
		inners = append(inners, tmpi...)

		tmpt := <-m.resTrapBuf[round]
		traps = append(traps, tmpt...)
	}

	return inners, traps
}

func (m *Member) commitments(round int) []atomcrypto.Commitment {
	return m.commitBuf[round]
}

func (m *Member) setShuffleOld(round int, old []atomcrypto.Ciphertext) {
	m.shufOld[round] = old
}

func (m *Member) shuffleOld(round int) []atomcrypto.Ciphertext {
	return m.shufOld[round]
}

func (m *Member) setReencryptOld(round int, old [][]atomcrypto.Ciphertext) {
	m.reencOld[round] = old
}

func (m *Member) reencryptOld(round int) [][]atomcrypto.Ciphertext {
	return m.reencOld[round]
}

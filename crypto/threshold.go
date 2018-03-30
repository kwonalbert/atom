package crypto

import (
	"errors"
	"log"
	"sync"

	"github.com/dedis/kyber"
	dkg "github.com/dedis/kyber/share/dkg/pedersen"
)

type Threshold struct {
	N        int
	t        int
	myIdx    int
	keyPair  *KeyPair
	groupKey PublicKey

	keyGen *dkg.DistKeyGenerator
	deals  map[int]*ThresholdDeal
	secret *dkg.DistKeyShare

	dealCnt  int       // channel to count number of deals received
	respCnt  chan bool // channel to count number of deals received
	dealCond *sync.Cond
}

func NewThreshold(myIdx, T int, key *KeyPair, longPubs []*PublicKey) *Threshold {
	N := len(longPubs)
	cpPub := CopyPubs(longPubs)
	myGroupKeys := make([]kyber.Point, N)
	for i := 0; i < N; i++ {
		myGroupKeys[i] = cpPub[i].p
	}

	keyGen, err := dkg.NewDistKeyGenerator(SUITE, key.Priv.s,
		myGroupKeys, T)
	if err != nil {
		log.Fatal("Could not create dist key gen", err)
	}
	deals, err := keyGen.Deals()
	if err != nil {
		log.Fatal("Could not create deals", err)
	}

	tdeals := make(map[int]*ThresholdDeal)
	for i := range deals {
		tdeals[i] = &ThresholdDeal{deals[i]}
	}

	t := &Threshold{
		t: T,
		N: N,

		myIdx:   myIdx,
		keyPair: key,

		keyGen: keyGen,
		deals:  tdeals,

		dealCnt:  0,
		respCnt:  make(chan bool, N*N),
		dealCond: sync.NewCond(new(sync.Mutex)),
	}

	return t
}

func (t *Threshold) AddDeal(deal *ThresholdDeal) (*ThresholdResponse, error) {
	t.dealCond.L.Lock()
	defer t.dealCond.L.Unlock()
	resp, err := t.keyGen.ProcessDeal(deal.D)
	if err != nil {
		return nil, err
	}
	t.dealCnt += 1
	if t.dealCnt == t.N-1 {
		t.dealCond.Broadcast()
	}
	return &ThresholdResponse{resp}, nil
}

func (t *Threshold) GetDeal(i int) *ThresholdDeal {
	return t.deals[i]
}

func (t *Threshold) AddResponse(resp *ThresholdResponse) error {
	t.dealCond.L.Lock()
	for t.dealCnt < t.N-1 {
		t.dealCond.Wait()
	}
	just, err := t.keyGen.ProcessResponse(resp.R)
	if just != nil {
		return errors.New("Justification not null")
	} else if err != nil {
		return err
	}
	t.dealCond.L.Unlock()
	t.respCnt <- true
	return nil
}

// Joint verifiable secret sharing setup
func (t *Threshold) JVSS() error {
	// Wait until it receives enough resps
	for i := 0; i < (t.N-1)*(t.N-1); i++ {
		<-t.respCnt
	}

	var err error
	t.secret, err = t.keyGen.DistKeyShare()
	if err != nil {
		return err
	}
	t.groupKey = PublicKey{t.secret.Public()}
	return nil
}

func (t *Threshold) PublicKey() *PublicKey {
	return &t.groupKey
}

// Given threshold group in terms of the index within the group,
// compute the lagrangian, and relevant point
func (t *Threshold) Lagrange(group []int) *PrivateKey {
	numer := SUITE.Scalar().One()
	denom := SUITE.Scalar().One()
	xServer := SUITE.Scalar().SetInt64(1 + int64(t.myIdx))
	for i := range group {
		if group[i] == t.myIdx {
			continue
		}
		numer = numer.Mul(numer, SUITE.Scalar().SetInt64(1+int64(group[i])))
		xj := SUITE.Scalar().SetInt64(1 + int64(group[i]))
		xj = xj.Sub(xj, xServer)
		denom = denom.Mul(denom, xj)
	}
	numer = numer.Div(numer, denom)
	key := SUITE.Scalar().Mul(numer, t.secret.Share.V)
	return &PrivateKey{key}
}

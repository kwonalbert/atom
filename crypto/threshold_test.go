package crypto

import (
	"log"
	"testing"
)

var M int = 1
var N = 5
var T = 4

func sendDeal(deal *ThresholdDeal, dst *Threshold, all []*Threshold) {
	resp, _ := dst.AddDeal(deal)
	for _, t := range all {
		if dst != t {
			err := t.AddResponse(resp)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
}

func TestThresholdSharing(t *testing.T) {
	keys, pubs, _ := GenKeys(N)
	ts := make([]*Threshold, N)
	sendss := make([][]*ThresholdDeal, N)
	recvss := make([][]*ThresholdResponse, N)
	for i := range ts {
		ts[i] = NewThreshold(i, T, keys[i], pubs)
		sendss[i] = make([]*ThresholdDeal, N)
		recvss[i] = make([]*ThresholdResponse, N)
	}

	errs := make(chan error)

	for i := range ts {
		for j := range ts {
			if i == j {
				continue
			}
			deal := ts[i].GetDeal(j)
			go sendDeal(deal, ts[j], ts)
		}
	}

	for i := range ts {
		go func(i int) {
			errs <- ts[i].JVSS()
		}(i)
	}

	for i := range ts {
		err := <-errs
		if err != nil {
			t.Error("Person", i, err)
		}
	}

	groupKey := ts[0].PublicKey()

	msg := GenRandMsg(5)
	nullKey := &PublicKey{SUITE.Point().Null()}

	ciphertext := Encrypt(groupKey, msg)

	fullGroup := make([]int, T)
	for i := 0; i < T; i++ {
		fullGroup[i] = i
	}

	for i := 0; i < T; i++ {
		share := ts[i].Lagrange(fullGroup)
		ciphertext = Reencrypt(share, nullKey, ciphertext)
	}

	for i := range ciphertext.C {
		if !ciphertext.C[i].Equal(msg[i]) {
			t.Error("Data corrupted!")
		}
	}
}

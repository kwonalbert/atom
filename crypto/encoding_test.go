package crypto

import (
	"bytes"
	"encoding/gob"
	"log"
	"testing"
)

func TestEncodeKey(t *testing.T) {
	keyPair := GenKey()

	var network bytes.Buffer // Stand-in for the network.
	// Create an encoder and send a value.
	enc := gob.NewEncoder(&network)
	err := enc.Encode(keyPair)
	if err != nil {
		t.Error(err)
	}

	// Create a decoder and receive a value.
	dec := gob.NewDecoder(&network)
	var res KeyPair
	err = dec.Decode(&res)
	if err != nil {
		log.Fatal("decode err:", err)
	}
	if !keyPair.Priv.s.Equal(res.Priv.s) ||
		!keyPair.Pub.p.Equal(res.Pub.p) {
		log.Fatal("Failed to encode key")
	}
}

func TestEncodeMsg(t *testing.T) {
	msg := GenPoints(size)

	var network bytes.Buffer // Stand-in for the network.
	// Create an encoder and send a value.
	enc := gob.NewEncoder(&network)
	err := enc.Encode(msg)
	if err != nil {
		t.Error(err)
	}

	// Create a decoder and receive a value.
	dec := gob.NewDecoder(&network)
	var res []*Point
	err = dec.Decode(&res)
	if err != nil {
		log.Fatal("decode err:", err)
	}

	for m := range msg {
		if !msg[m].Equal(res[m]) {
			t.Error("Failed to encode msg")
		}
	}
}

func TestEncodeThreshold(t *testing.T) {
	keys, pubs, _ := GenKeys(N)
	ts := make([]*Threshold, N)
	sendss := make([][]*ThresholdDeal, N)
	recvss := make([][]*ThresholdResponse, N)
	for i := range ts {
		cp := CopyPubs(pubs) // done to avoid weird race condition
		ts[i] = NewThreshold(i, T, keys[i], cp)
		sendss[i] = make([]*ThresholdDeal, N)
		recvss[i] = make([]*ThresholdResponse, N)
	}

	deal := ts[0].GetDeal(1)
	b, _ := deal.MarshalBinary()
	dcp := new(ThresholdDeal)
	dcp.UnmarshalBinary(b)
	//fmt.Println(deal.D.Deal, dcp.D.Deal)
}

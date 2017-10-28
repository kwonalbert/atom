package server

import (
	"testing"

	"github.com/kwonalbert/atom/common"
	"github.com/kwonalbert/atom/crypto"
)

func BenchmarkMixing(b *testing.B) {
	keyPair := crypto.GenKey()
	group := &common.Group{
		GroupKey: keyPair.Pub,
	}
	member := Member{
		group: group,
	}
	numMsgs := 16384
	ciphertexts := make([]crypto.Ciphertext, numMsgs)
	msgs := crypto.GenRandMsgs(numMsgs, 1)
	for c := range ciphertexts {
		ciphertexts[c] = crypto.Encrypt(keyPair.Pub, msgs[c])
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		member.shuffle(ciphertexts)
	}
}

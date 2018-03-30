package crypto

import (
	"runtime"
	"sync"

	"github.com/dedis/kyber/util/random"
)

// Reblind the messages and randomly permute them
func Shuffle(X *PublicKey, cs []Ciphertext) []Ciphertext {
	rnd := random.New()
	k := len(cs)

	ciphertexts := make([]Ciphertext, k)
	tmp := make([]Ciphertext, k)

	chunks := runtime.NumCPU()
	div := k / chunks
	if k < chunks {
		div = 1
		chunks = k
	} else if k%chunks != 0 {
		div++
	}

	wg := new(sync.WaitGroup)
	wg.Add(chunks)
	for d := 0; d < chunks; d++ {
		start := d * div
		end := (d + 1) * div
		if end > k {
			end = k
		}
		go func(start, end int) {
			defer wg.Done()
			for i := start; i < end; i++ {
				tmp[i] = Reblind(X, cs[i])
			}
		}(start, end)
	}
	wg.Wait()

	// for i := range cs {
	// 	tmp[i] = Reblind(X, cs[i])
	// }

	pi := make([]int, k)
	for i := 0; i < k; i++ { // Initialize a trivial permutation
		pi[i] = i
	}
	for i := k - 1; i > 0; i-- { // Shuffle by random swaps
		j := int(randUint64(rnd) % uint64(i+1))
		if j != i {
			t := pi[j]
			pi[j] = pi[i]
			pi[i] = t
		}
	}

	for i := range cs {
		ciphertexts[i] = tmp[pi[i]]
	}
	return ciphertexts
}

package crypto

import (
	"encoding/binary"
	"runtime"
	"sync"

	"github.com/dedis/kyber/group/edwards25519"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/kyber/xof/blake2xb"

	"golang.org/x/crypto/sha3"
)

var SUITE = edwards25519.NewBlakeSHA256Ed25519WithRand(blake2xb.New(nil))
var refPt = SUITE.Point()

// Basic ElGamal encryption
func Encrypt(X *PublicKey, msg Message) Ciphertext {
	rnd := random.New()
	R := make([]*Point, len(msg))
	C := make([]*Point, len(msg))
	for idx := range msg {
		r := SUITE.Scalar().Pick(rnd)
		R[idx] = &Point{SUITE.Point().Mul(r, nil)}
		C[idx] = &Point{SUITE.Point().Add(msg[idx].p, SUITE.Point().Mul(r, X.p))}
	}
	return Ciphertext{
		R: R,
		C: C,
		Y: nil,
	}
}

// Basic ElGamal decryption
func Decrypt(x *PrivateKey, c Ciphertext) Message {
	msg := make([]*Point, len(c.C))
	for idx := range c.C {
		blind := SUITE.Point().Mul(x.s, c.R[idx].p)
		msg[idx] = &Point{blind.Sub(c.C[idx].p, blind)}
	}
	return msg
}

// Reblind ciphertext c using publickey X
func Reblind(X *PublicKey, c Ciphertext) Ciphertext {
	rnd := random.New()
	for idx := range c.C {
		r := SUITE.Scalar().Pick(rnd)
		newR := SUITE.Point().Mul(r, nil)
		newBlind := SUITE.Point().Mul(r, X.p)

		c.R[idx].p = c.R[idx].p.Add(c.R[idx].p, newR)
		c.C[idx].p = c.C[idx].p.Add(c.C[idx].p, newBlind)
	}
	return c
}

// Decrypt ciphertext c using x and reencrypt using XBar
func Reencrypt(x *PrivateKey, XBar *PublicKey, c Ciphertext) Ciphertext {
	if c.Y == nil {
		c.Y = c.R
		c.R = make([]*Point, len(c.Y))
		for idx := range c.R {
			c.R[idx] = &Point{SUITE.Point().Null()}
		}
	}
	rnd := random.New()

	ciphertext := Ciphertext{
		R: make([]*Point, len(c.R)),
		C: make([]*Point, len(c.C)),
		Y: make([]*Point, len(c.Y)),
	}
	for idx := range c.C {
		blind := SUITE.Point().Mul(x.s, c.Y[idx].p)
		ctmp := blind.Sub(c.C[idx].p, blind)

		rBar := SUITE.Scalar().Pick(rnd)
		newR := SUITE.Point().Mul(rBar, nil)
		newR = newR.Add(c.R[idx].p, newR)

		newBlind := SUITE.Point().Mul(rBar, XBar.p)
		newC := ctmp.Add(ctmp, newBlind)

		ciphertext.R[idx] = &Point{newR}
		ciphertext.C[idx] = &Point{newC}
		ciphertext.Y[idx] = c.Y[idx]
	}
	return ciphertext
}

func ReencryptBatches(priv *PrivateKey, pubKeys []*PublicKey, batches [][]Ciphertext) [][]Ciphertext {
	numBatches := len(batches)
	batchSize := len(batches[0])
	k := numBatches * batchSize
	ciphertexts := make([]Ciphertext, k)
	pubs := make([]*PublicKey, k)
	idx := 0
	for b := range batches {
		for i := range batches[b] {
			ciphertexts[idx] = batches[b][i]
			pubs[idx] = pubKeys[b]
			idx++
		}
	}

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
				ciphertexts[i] = Reencrypt(priv, pubs[i], ciphertexts[i])
			}
		}(start, end)
	}
	wg.Wait()

	result := make([][]Ciphertext, len(batches))
	idx = 0
	for b := range batches {
		result[b] = make([]Ciphertext, len(batches[b]))
		for i := range batches[b] {
			result[b][i] = ciphertexts[idx]
			idx++

		}
	}

	return result
}

func Commit(trap Trap) Commitment {
	buf := make([]byte, 8)
	gid := uint64(trap.Gid)
	binary.PutUvarint(buf, gid)
	b := append(buf, trap.Nonce...)
	return sha3.Sum256(b)
}

func VerifyCommitment(trap Trap, comm Commitment) bool {
	buf := make([]byte, 8)
	gid := uint64(trap.Gid)
	binary.PutUvarint(buf, gid)
	b := append(buf, trap.Nonce...)
	res := sha3.Sum256(b)
	if res == comm {
		return true
	} else {
		return false
	}
}

package crypto

import (
	"errors"
	"log"
	"runtime"
	"sync"

	"golang.org/x/crypto/sha3"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/proof"
	"github.com/dedis/kyber/shuffle"
	"github.com/dedis/kyber/util/random"
)

func ProveEncrypt(X *PublicKey, msg Message) (Ciphertext, EncProof) {
	rnd := random.New()
	R := make([]*Point, len(msg))
	C := make([]*Point, len(msg))
	proof := EncProof{
		S: make([]*Point, len(msg)),
		U: make([]*Scalar, len(msg)),
	}
	Xbin, _ := X.MarshalBinary()
	for idx := range msg {
		r := SUITE.Scalar().Pick(rnd)
		R[idx] = &Point{SUITE.Point().Mul(r, nil)}
		C[idx] = &Point{SUITE.Point().Add(msg[idx].p, SUITE.Point().Mul(r, X.p))}

		s := SUITE.Scalar().Pick(rnd)
		S := SUITE.Point().Mul(s, nil)

		Cbin, _ := C[idx].MarshalBinary()
		sbin, _ := S.MarshalBinary()
		inp := append(Cbin, sbin...)
		inp = append(inp, Xbin...)
		tbin := sha3.Sum256(inp)
		t := SUITE.Scalar().SetBytes(tbin[:])
		u := s.Add(s, t.Mul(t, r))
		proof.S[idx] = &Point{S}
		proof.U[idx] = &Scalar{u}
	}
	return Ciphertext{
		R: R,
		C: C,
		Y: nil,
	}, proof
}

func VerifyEncrypt(X *PublicKey, c Ciphertext, proof EncProof) error {
	Xbin, _ := X.MarshalBinary()
	for idx := range c.C {
		U := SUITE.Point().Mul(proof.U[idx].s, nil)
		S := proof.S[idx].p

		Cbin, _ := c.C[idx].MarshalBinary()
		sbin, _ := S.MarshalBinary()
		inp := append(Cbin, sbin...)
		inp = append(inp, Xbin...)
		tbin := sha3.Sum256(inp)
		t := SUITE.Scalar().SetBytes(tbin[:])
		R := SUITE.Point().Mul(t, c.R[idx].p)
		R = R.Add(S, R)
		if !U.Equal(R) {
			return errors.New("Encproof verify failed")
		}
	}
	return nil
}

func ProveReencrypt(x *PrivateKey, XBar *PublicKey, c Ciphertext) (Ciphertext, ReencProof) {
	if c.Y == nil {
		c.Y = c.R
		c.R = make([]*Point, len(c.Y))
		for idx := range c.R {
			c.R[idx] = &Point{SUITE.Point().Null()}
		}
	}
	rnd := random.New()

	proofs := make([][]byte, len(c.C))

	p := proof.Rep("Y'-Y", "-h", "X", "r", "B")

	ciphertext := Ciphertext{
		R: make([]*Point, len(c.R)),
		C: make([]*Point, len(c.C)),
		Y: make([]*Point, len(c.Y)),
	}

	negx := SUITE.Scalar().Neg(x.s)
	for idx := range c.C {
		pub := map[string]kyber.Point{"B": XBar.p}
		sec := map[string]kyber.Scalar{"-h": negx}

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

		pub["X"] = c.Y[idx].p
		sec["r"] = rBar
		pub["Y'-Y"] = SUITE.Point().Sub(ctmp, c.C[idx].p)
		prover := p.Prover(SUITE, sec, pub, nil)
		proof, err := proof.HashProve(SUITE, "Decrypt", prover)
		if err != nil {
			log.Fatal("Proof gen err:", err)
		}
		proofs[idx] = proof
	}
	return ciphertext, proofs
}

func ProveReencryptBatches(priv *PrivateKey, neighborKeys []*PublicKey, batches [][]Ciphertext) ([][]Ciphertext, [][]ReencProof) {
	numBatches := len(batches)
	batchSize := len(batches[0])
	k := numBatches * batchSize
	ciphertexts := make([]Ciphertext, k)
	proofs := make([]ReencProof, k)
	pubs := make([]*PublicKey, k)
	idx := 0
	for b := range batches {
		for i := range batches[b] {
			ciphertexts[idx] = batches[b][i]
			pubs[idx] = neighborKeys[b]
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
				ciphertexts[i], proofs[i] = ProveReencrypt(priv, pubs[i], ciphertexts[i])
			}
		}(start, end)
	}
	wg.Wait()

	resultc := make([][]Ciphertext, len(batches))
	resultp := make([][]ReencProof, len(batches))

	idx = 0
	for b := range batches {
		resultc[b] = make([]Ciphertext, len(batches[b]))
		resultp[b] = make([]ReencProof, len(batches[b]))
		for i := range batches[b] {
			resultc[b][i] = ciphertexts[idx]
			resultp[b][i] = proofs[idx]
			idx++
		}
	}

	return resultc, resultp
}

func VerifyReencrypt(X *PublicKey, old, new Ciphertext, proofs ReencProof) error {
	p := proof.Rep("Y'-Y", "-h", "X", "r", "B")
	for idx := range new.C {
		pub := map[string]kyber.Point{"B": X.p}
		pub["X"] = new.Y[idx].p
		pub["Y'-Y"] = SUITE.Point().Sub(new.C[idx].p, old.C[idx].p)
		verifier := p.Verifier(SUITE, pub)
		err := proof.HashVerify(SUITE, "Decrypt", verifier, proofs[idx])
		if err != nil {
			return err
		}
	}
	return nil
}

func VerifyReencryptBatches(ob, nb [][]Ciphertext, proofs [][]ReencProof, neighborKeys []*PublicKey) bool {
	for b := range nb {
		for c := range nb[b] {
			err := VerifyReencrypt(neighborKeys[b], ob[b][c], nb[b][c], proofs[b][c])
			if err != nil {
				log.Println("Incorrect reencrypt proof:", err)
				return false
			}
		}
	}
	return true
}

// Reblind and also return reblinding factors for prove shuffle
func reblind(X *PublicKey, c Ciphertext) (Ciphertext, []*Scalar) {
	rnd := random.New()
	blinds := make([]*Scalar, len(c.C))
	nc := Ciphertext{
		R: make([]*Point, len(c.R)),
		C: make([]*Point, len(c.C)),
	}
	for idx := range c.C {
		r := SUITE.Scalar().Pick(rnd)
		blinds[idx] = &Scalar{r}
		newR := SUITE.Point().Mul(r, nil)
		newBlind := SUITE.Point().Mul(r, X.p)

		nc.R[idx] = &Point{SUITE.Point().Add(c.R[idx].p, newR)}
		nc.C[idx] = &Point{SUITE.Point().Add(c.C[idx].p, newBlind)}
	}
	return nc, blinds
}

func ProveShuffle(X *PublicKey, cs []Ciphertext) ([]Ciphertext, ShufProof) {
	rnd := random.New()
	k := len(cs)

	ciphertexts := make([]Ciphertext, k)
	tmp := make([]Ciphertext, k)
	blinds := make([][]*Scalar, k)

	chunks := runtime.NumCPU()
	div := k / chunks
	if k < chunks {
		div = 1
		chunks = k
	} else if k%chunks != 0 {
		div += 1
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
				tmp[i], blinds[i] = reblind(X, cs[i])
			}
		}(start, end)
	}
	wg.Wait()

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

	proofs := make([][]byte, len(cs[0].C))
	wg.Add(len(cs[0].C))
	for idx := range cs[0].C {
		go func(idx int) {
			defer wg.Done()
			ps := shuffle.PairShuffle{}
			ps.Init(SUITE, k)

			R := make([]kyber.Point, k)
			C := make([]kyber.Point, k)
			r := make([]kyber.Scalar, k)
			for c := range cs {
				R[c] = cs[c].R[idx].p
				C[c] = cs[c].C[idx].p
				r[c] = blinds[c][idx].s
			}

			prover := func(ctx proof.ProverContext) error {
				return ps.Prove(pi, nil, X.p, r, R, C, rnd, ctx)
			}
			proof, err := proof.HashProve(SUITE, "PairShuffle", prover)
			if err != nil {
				log.Fatal("Error creating proof:", err)
			}
			proofs[idx] = proof
		}(idx)
	}
	wg.Wait()
	return ciphertexts, proofs
}

func VerifyShuffle(X *PublicKey, oc, nc []Ciphertext, proofs ShufProof) error {
	if len(oc) != len(nc) {
		return errors.New("Mismatching length")
	}
	k := len(nc)

	errChan := make(chan error)
	for idx := range oc[0].C {
		go func(idx int) {
			ps := shuffle.PairShuffle{}
			ps.Init(SUITE, len(nc))

			R := make([]kyber.Point, k)
			C := make([]kyber.Point, k)
			Rbar := make([]kyber.Point, k)
			Cbar := make([]kyber.Point, k)
			for c := range oc {
				R[c] = oc[c].R[idx].p
				C[c] = oc[c].C[idx].p
				Rbar[c] = nc[c].R[idx].p
				Cbar[c] = nc[c].C[idx].p
			}

			verifier := func(ctx proof.VerifierContext) error {
				return ps.Verify(nil, X.p, R, C, Rbar, Cbar, ctx)
			}
			errChan <- proof.HashVerify(SUITE, "PairShuffle", verifier, proofs[idx])
		}(idx)
	}

	for _ = range oc[0].C {
		err := <-errChan
		if err != nil {
			return err
		}
	}

	return nil
}

package crypto

import "testing"

func TestNIZKEncrypt(t *testing.T) {
	key := GenKey()
	x, X := key.Priv, key.Pub
	msg := GenRandMsg(size)

	c, proof := ProveEncrypt(X, msg)

	err := VerifyEncrypt(X, c, proof)
	if err != nil {
		t.Error("Prove fail:", err)
	}

	res := Decrypt(x, c)
	for m := range msg {
		if !msg[m].Equal(res[m]) {
			t.Error("Mismatched plaintext message.")
		}
	}
}

func TestNIZKRencrypt(t *testing.T) {
	key1 := GenKey()
	x1, X1 := key1.Priv, key1.Pub
	key2 := GenKey()
	x2, X2 := key2.Priv, key2.Pub

	msg := GenRandMsg(size)
	ciphertext := Encrypt(X1, msg)

	reenc, proofs := ProveReencrypt(x1, X2, ciphertext)

	err := VerifyReencrypt(X2, ciphertext, reenc, proofs)
	if err != nil {
		t.Error("Prove fail:", err)
	}

	res := Decrypt(x2, reenc)
	for m := range msg {
		if !msg[m].Equal(res[m]) {
			t.Error("Mismatched plaintext message.")
		}
	}
}

func TestNIZKShuffle(t *testing.T) {
	key := GenKey()
	x, X := key.Priv, key.Pub

	msgs := GenRandMsgs(3, size)
	ciphertexts := make([]Ciphertext, 3)
	for m := range msgs {
		ciphertexts[m] = Encrypt(X, msgs[m])
	}

	shuffled, proofs := ProveShuffle(X, ciphertexts)

	results := make([]Message, 3)
	for r := range results {
		results[r] = Decrypt(x, shuffled[r])
	}

	for r := range results {
		if !isMemberMessage(results[r], msgs) {
			t.Error("Missing message.")
		}
	}

	err := VerifyShuffle(X, ciphertexts, shuffled, proofs)
	if err != nil {
		t.Error("VerifyShuffle failed:", err)
	}
}

func BenchmarkEncryptProve(b *testing.B) {
	key := GenKey()
	_, X := key.Priv, key.Pub
	msg := GenRandMsg(1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ProveEncrypt(X, msg)
	}
}

func BenchmarkEncryptVerify(b *testing.B) {
	key := GenKey()
	_, X := key.Priv, key.Pub
	msg := GenRandMsg(1)

	c, proof := ProveEncrypt(X, msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyEncrypt(X, c, proof)
	}
}

func BenchmarkRencryptProve(b *testing.B) {
	key1 := GenKey()
	x1, X1 := key1.Priv, key1.Pub
	key2 := GenKey()
	_, X2 := key2.Priv, key2.Pub

	msg := GenRandMsg(1)
	ciphertext := Encrypt(X1, msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ProveReencrypt(x1, X2, ciphertext)
	}
}

func BenchmarkRencryptVerify(b *testing.B) {
	key1 := GenKey()
	x1, X1 := key1.Priv, key1.Pub
	key2 := GenKey()
	_, X2 := key2.Priv, key2.Pub

	msg := GenRandMsg(1)
	ciphertext := Encrypt(X1, msg)

	reenc, proofs := ProveReencrypt(x1, X2, ciphertext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyReencrypt(X2, ciphertext, reenc, proofs)
	}
}

func BenchmarkShuffleProve1024(b *testing.B) {
	numPts := 1024
	key := GenKey()
	_, X := key.Priv, key.Pub

	msgs := GenRandMsgs(numPts, 1)
	ciphertexts := make([]Ciphertext, numPts)
	for m := range msgs {
		ciphertexts[m] = Encrypt(X, msgs[m])
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ProveShuffle(X, ciphertexts)
	}
}

func BenchmarkShuffleProve2048(b *testing.B) {
	numPts := 2048
	key := GenKey()
	_, X := key.Priv, key.Pub

	msgs := GenRandMsgs(numPts, 1)
	ciphertexts := make([]Ciphertext, numPts)
	for m := range msgs {
		ciphertexts[m] = Encrypt(X, msgs[m])
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ProveShuffle(X, ciphertexts)
	}
}

func BenchmarkShuffleVerify1024(b *testing.B) {
	numPts := 1024
	key := GenKey()
	_, X := key.Priv, key.Pub

	msgs := GenRandMsgs(numPts, 1)
	ciphertexts := make([]Ciphertext, numPts)
	for m := range msgs {
		ciphertexts[m] = Encrypt(X, msgs[m])
	}

	shuffled, proofs := ProveShuffle(X, ciphertexts)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyShuffle(X, ciphertexts, shuffled, proofs)
	}
}

func BenchmarkShuffleVerify2048(b *testing.B) {
	numPts := 2048
	key := GenKey()
	_, X := key.Priv, key.Pub

	msgs := GenRandMsgs(numPts, 1)
	ciphertexts := make([]Ciphertext, numPts)
	for m := range msgs {
		ciphertexts[m] = Encrypt(X, msgs[m])
	}

	shuffled, proofs := ProveShuffle(X, ciphertexts)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyShuffle(X, ciphertexts, shuffled, proofs)
	}
}

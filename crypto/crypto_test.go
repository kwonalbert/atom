package crypto

import "testing"

var size = 1
var num = 5

func isEqualMessage(m1, m2 Message) bool {
	same := true
	for i := range m1 {
		same = same && m1[i].Equal(m2[i])
	}
	return same
}

func isMemberMessage(msg Message, msgs []Message) bool {
	for m := range msgs {
		if isEqualMessage(msg, msgs[m]) {
			return true
		}
	}
	return false
}

func TestComebineKeys(t *testing.T) {
	_, pubs, secs := GenKeys(N)
	cSec := CombinePrivateKeys(secs)
	cPub := CombinePublicKeys(pubs)
	if !PubFromPriv(cSec).Equal(cPub) {
		t.Error("Mismatched combined keys")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := GenKey()
	x, X := key.Priv, key.Pub
	msg := GenRandMsg(size)

	ciphertext := Encrypt(X, msg)
	res := Decrypt(x, ciphertext)

	for m := range msg {
		if !msg[m].Equal(res[m]) {
			t.Error("Mismatched plaintext message.")
		}
	}
}

func TestReblind(t *testing.T) {
	key := GenKey()
	x, X := key.Priv, key.Pub
	msg := GenRandMsg(size)

	ciphertext := Encrypt(X, msg)

	reblinded := Reblind(X, ciphertext)

	exp := Decrypt(x, ciphertext)
	res := Decrypt(x, reblinded)

	for m := range exp {
		if !msg[m].Equal(res[m]) {
			t.Error("Mismatched plaintext message.")
		}
	}
}

func TestReencrypt(t *testing.T) {
	key1 := GenKey()
	x1, X1 := key1.Priv, key1.Pub
	key2 := GenKey()
	x2, X2 := key2.Priv, key2.Pub
	Xcombined := CombinePublicKeys([]*PublicKey{X1, X2})

	key3 := GenKey()
	y, Y := key3.Priv, key3.Pub

	msg := GenRandMsg(size)
	ciphertext := Encrypt(Xcombined, msg)

	reenc := Reencrypt(x1, Y, ciphertext)
	reenc = Reencrypt(x2, Y, reenc)

	res := Decrypt(y, reenc)
	for m := range msg {
		if !msg[m].Equal(res[m]) {
			t.Error("Mismatched plaintext message.")
		}
	}
}

func TestShuffle(t *testing.T) {
	key := GenKey()
	x, X := key.Priv, key.Pub

	msgs := GenRandMsgs(num, size)
	ciphertexts := make([]Ciphertext, num)
	for m := range msgs {
		ciphertexts[m] = Encrypt(X, msgs[m])
	}

	shuffled := Shuffle(X, ciphertexts)

	results := make([]Message, num)
	for r := range results {
		results[r] = Decrypt(x, shuffled[r])
	}

	for r := range results {
		if !isMemberMessage(results[r], msgs) {
			t.Error("Missing message.")
		}
	}
}

func TestCCA2(t *testing.T) {
	nonce := make([]byte, 24)
	key := GenKey()
	x, X := key.Priv, key.Pub

	msg := make([]byte, 160)
	copy(msg, []byte("Hello World"))
	inner := CCA2Encrypt(msg, nonce, X)

	decMsg, err := CCA2Decrypt(inner, nonce, x, X)
	if err != nil {
		t.Error(err)
	} else {
		if len(msg) != len(decMsg) {
			t.Error("Msg length mismatch")
		}
		for m := range msg {
			if msg[m] != decMsg[m] {
				t.Error("Msg mismatch")
			}
		}
	}

}

func BenchmarkEncrypt(b *testing.B) {
	key := GenKey()
	_, X := key.Priv, key.Pub
	msg := GenRandMsg(size)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(X, msg)
	}
}

func BenchmarkReencrypt(b *testing.B) {
	key1 := GenKey()
	x1, X1 := key1.Priv, key1.Pub
	key2 := GenKey()
	_, X2 := key2.Priv, key2.Pub
	Xcombined := CombinePublicKeys([]*PublicKey{X1, X2})

	key3 := GenKey()
	_, Y := key3.Priv, key3.Pub

	msg := GenRandMsg(size)
	ciphertext := Encrypt(Xcombined, msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Reencrypt(x1, Y, ciphertext)
	}
}

func BenchmarkShuffle1024(b *testing.B) {
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
		Shuffle(X, ciphertexts)
	}
}

func BenchmarkShuffle2048(b *testing.B) {
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
		Shuffle(X, ciphertexts)
	}
}

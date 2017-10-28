package crypto

import (
	"errors"
	"log"

	"github.com/dedis/kyber/cipher"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/sha3"
)

func CCA2Encrypt(plaintext []byte, nonce []byte, X *PublicKey) InnerCiphertext {
	rnd := SUITE.Cipher(cipher.RandomKey)

	r := SUITE.Scalar().Pick(rnd)
	R := SUITE.Point().Mul(r, nil)
	shared := SUITE.Point().Mul(r, X.p)

	sharedBytes, err := shared.MarshalBinary()
	if err != nil {
		log.Fatal("Could not marshal rand")
	}
	pubBytes, err := X.p.MarshalBinary()
	if err != nil {
		log.Fatal("Could not marshal trustee key")
	}
	key_nonce := append(pubBytes, sharedBytes...)

	var key [32]byte
	sha3.ShakeSum128(key[:], key_nonce)
	var nonce24 [24]byte
	copy(nonce24[:], nonce)

	ciphertext := secretbox.Seal(nil, plaintext, &nonce24, &key)
	return InnerCiphertext{
		R: &Point{R},
		C: ciphertext,
	}
}

func CCA2Decrypt(inner InnerCiphertext, nonce []byte,
	x *PrivateKey, X *PublicKey) ([]byte, error) {

	shared := SUITE.Point().Mul(x.s, inner.R.p)
	sharedBytes, err := shared.MarshalBinary()
	if err != nil {
		log.Fatal("Could not marshal rand")
	}
	pubBytes, err := X.p.MarshalBinary()
	if err != nil {
		log.Fatal("Could not marshal trustee key")
	}
	key_nonce := append(pubBytes, sharedBytes...)

	var key [32]byte
	sha3.ShakeSum128(key[:], key_nonce)
	var nonce24 [24]byte
	copy(nonce24[:], nonce)

	msg, auth := secretbox.Open(nil, inner.C, &nonce24, &key)
	if !auth {
		return nil, errors.New("Misauthenticated msg")
	}
	return msg, nil
}

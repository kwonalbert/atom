package crypto

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"

	"github.com/dedis/crypto/abstract"
)

func GenKey() *KeyPair {
	rnd := SUITE.Cipher(abstract.RandomKey)
	x := SUITE.Scalar().Pick(rnd)
	X := SUITE.Point().Mul(x, nil)
	return &KeyPair{
		Priv: &PrivateKey{x},
		Pub:  &PublicKey{X},
	}
}

func NullKey() *PublicKey {
	return &PublicKey{SUITE.Point().Null()}
}

func PubFromPriv(priv *PrivateKey) *PublicKey {
	return &PublicKey{SUITE.Point().Mul(priv.s, nil)}
}

func GenKeys(N int) ([]*KeyPair, []*PublicKey, []*PrivateKey) {
	keys := make([]*KeyPair, N)
	pubs := make([]*PublicKey, N)
	privs := make([]*PrivateKey, N)
	for k := range keys {
		keys[k] = GenKey()
		pubs[k] = keys[k].Pub
		privs[k] = keys[k].Priv
	}
	return keys, pubs, privs
}

// The combined private key for a bunch of nodes
func CombinePrivateKeys(privs []*PrivateKey) *PrivateKey {
	t := SUITE.Scalar().Zero()
	for i := range privs {
		t = t.Add(t, privs[i].s)
	}
	return &PrivateKey{t}
}

// The combined public key for a bunch of nodes
func CombinePublicKeys(pubs []*PublicKey) *PublicKey {
	h := SUITE.Point().Null()
	for i := range pubs {
		h = h.Add(h, pubs[i].p)
	}
	return &PublicKey{h}
}

func ReadKeys(fn string) ([]HexKeyPair, error) {
	file, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	bs, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var keys []HexKeyPair
	err = json.Unmarshal(bs, &keys)
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func DumpPrivKey(priv *PrivateKey) string {
	b, err := priv.s.MarshalBinary()
	if err != nil {
		log.Fatal("secret key err:", err)
	}
	return hex.EncodeToString(b)
}

func DumpPubKey(pub *PublicKey) string {
	b, err := pub.p.MarshalBinary()
	if err != nil {
		log.Fatal("public key err:", err)
	}
	return hex.EncodeToString(b)
}

func DumpKey(keyPair *KeyPair) HexKeyPair {
	return HexKeyPair{
		Priv: DumpPrivKey(keyPair.Priv),
		Pub:  DumpPubKey(keyPair.Pub),
	}
}

func LoadPrivKey(priv string) *PrivateKey {
	pb, err := hex.DecodeString(priv)
	if err != nil {
		log.Fatal("Loading malformed keys", err)
	}
	privKey := SUITE.Scalar()
	err = privKey.UnmarshalBinary(pb)
	if err != nil {
		log.Fatal("Loading malformed keys", err)
	}
	return &PrivateKey{privKey}
}

func LoadPubKey(pub string) *PublicKey {
	pb, err := hex.DecodeString(pub)
	if err != nil {
		log.Fatal("Loading malformed keys", err)
	}
	pubKey := SUITE.Point()
	err = pubKey.UnmarshalBinary(pb)
	if err != nil {
		log.Fatal("Loading malformed keys", err)
	}
	return &PublicKey{pubKey}
}

func LoadKey(key HexKeyPair) *KeyPair {
	return &KeyPair{
		Priv: LoadPrivKey(key.Priv),
		Pub:  LoadPubKey(key.Pub),
	}
}

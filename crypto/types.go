package crypto

import (
	"github.com/dedis/kyber"
	dkg "github.com/dedis/kyber/share/dkg/pedersen"
)

const (
	NONCE_LEN = 16
)

const (
	MSG   = 0
	TRAP  = 1
	OTHER = 2
)

type MsgType byte

type Point struct {
	p kyber.Point
}

func (p1 *Point) Equal(p2 *Point) bool {
	return p1.p.Equal(p2.p)
}

func (p *Point) String() string {
	return p.p.String()
}

func (p1 *PublicKey) Equal(p2 *PublicKey) bool {
	return p1.p.Equal(p2.p)
}

func (p *PublicKey) String() string {
	return p.p.String()
}

type Scalar struct {
	s kyber.Scalar
}

func (s1 *Scalar) Equal(s2 *Scalar) bool {
	return s1.s.Equal(s2.s)
}

func (s *Scalar) String() string {
	return s.s.String()
}

func (s1 *PrivateKey) Equal(s2 *PrivateKey) bool {
	return s1.s.Equal(s2.s)
}

func (s *PrivateKey) String() string {
	return s.s.String()
}

type Message []*Point

func (m1 Message) Equal(m2 Message) bool {
	ok := true
	for m := range m1 {
		ok = ok && m1[m].p.Equal(m2[m].p)
	}
	return ok
}

type PrivateKey Scalar
type PublicKey Point

type KeyPair struct {
	Priv *PrivateKey
	Pub  *PublicKey
}

func (k *KeyPair) String() string {
	return "(" + k.Priv.String() + ", " + k.Pub.String() + ")"
}

type TrusteeKey struct {
	Round int // trustee keys are per round
	KeyPair
}

type HexKeyPair struct {
	Priv string
	Pub  string
}

type InnerCiphertext struct {
	R *Point
	C []byte
}

// single user-submitted ciphertext
type Ciphertext struct {
	R []*Point
	C []*Point
	Y []*Point
}

type Trap struct {
	Gid   int
	Nonce []byte
}

type Commitment [32]byte

func (c Commitment) String() string {
	buf := make([]byte, 32)
	copy(buf, c[:])
	return string(buf)
}

type EncProof struct {
	S []*Point
	U []*Scalar
}

type ShufProof [][]byte

type ReencProof [][]byte

type ThresholdDeal struct {
	D *dkg.Deal
}

type ThresholdResponse struct {
	R *dkg.Response
}

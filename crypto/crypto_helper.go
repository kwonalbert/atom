package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/random"
)

func PickLen() int {
	return refPt.EmbedLen()
}

func compareArray(arr1, arr2 []byte) bool {
	if len(arr1) != len(arr2) {
		return false
	}
	for i := range arr1 {
		if arr1[i] != arr2[i] {
			return false
		}
	}
	return true
}

func GenMsg(msg []byte) Message {
	plaintext := append(msg, byte(MSG))

	for {
		var pts []*Point
		var pt kyber.Point
		done := false
		i := 0
		l := PickLen()
		for !done {
			start := i * l
			end := (i + 1) * l
			if end > len(plaintext) {
				end = len(plaintext)
			}
			pt = SUITE.Point().Embed(plaintext[start:end], random.New())
			pts = append(pts, &Point{pt})
			i++
			done = end == len(plaintext)
		}
		res, ty, err := ExtractPlaintext(pts)
		if err == nil && ty == MSG && compareArray(msg, res) {
			return pts
		}
		fmt.Println("fail msg!")
	}
}

func GenMsgs(plaintexts [][]byte) []Message {
	msgs := make([]Message, len(plaintexts))
	for m := range msgs {
		msgs[m] = GenMsg(plaintexts[m])
	}
	return msgs
}

func GenRandMsg(numPts int) Message {
	msg := make([]*Point, numPts)
	rnd := random.New()
	for m := range msg {
		tmp := SUITE.Scalar().Pick(rnd)
		msg[m] = &Point{SUITE.Point().Mul(tmp, nil)}
	}
	return msg
}

func GenPoints(numPts int) []*Point {
	msg := make([]*Point, numPts)
	rnd := random.New()
	for m := range msg {
		tmp := SUITE.Scalar().Pick(rnd)
		msg[m] = &Point{SUITE.Point().Mul(tmp, nil)}
	}
	return msg
}

func GenRandMsgs(numMsg, numPts int) []Message {
	msgs := make([]Message, numMsg)
	for m := range msgs {
		msgs[m] = GenRandMsg(numPts)
	}
	return msgs
}

func GenTrap(gid int) Trap {
	buf := make([]byte, NONCE_LEN)
	n, err := rand.Read(buf)
	if n != NONCE_LEN {
		log.Fatal("Could not read enough rand bytes")
	} else if err != nil {
		log.Fatal("Could not read rand bytes:", err)
	}
	return Trap{Gid: gid, Nonce: buf}
}

func TrapToMessage(trap Trap, numPts int) (Message, error) {
	buf, err := (&trap).MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf = append(buf, byte(TRAP))
	for {
		pt := SUITE.Point().Embed(buf, random.New())
		res, err := pt.Data()
		if err != nil || !compareArray(buf, res) {
			fmt.Println("fail trap!")
			continue
		}
		msg := make([]*Point, numPts)
		for m := range msg {
			msg[m] = &Point{pt}
		}
		return msg, nil
	}
}

func ExtractMessages(ciphertexts []Ciphertext) []Message {
	msgs := make([]Message, len(ciphertexts))
	for c, ciphertext := range ciphertexts {
		msgs[c] = ciphertext.C
	}
	return msgs
}

func ExtractPlaintext(msg Message) ([]byte, MsgType, error) {
	var plaintext []byte
	for m := range msg {
		p, err := msg[m].p.Data()
		if err != nil {
			return nil, MsgType(byte(OTHER)), err
		}
		plaintext = append(plaintext, p...)
	}
	msgType := plaintext[len(plaintext)-1]
	if msgType == TRAP {
		plaintext = plaintext[:4+NONCE_LEN]
	} else if msgType == MSG {
		plaintext = plaintext[:len(plaintext)-1]
	}
	return plaintext, MsgType(msgType), nil
}

func ExtractPlaintexts(msgs []Message) ([][]byte, []MsgType, error) {
	plaintexts := make([][]byte, len(msgs))
	msgType := make([]MsgType, len(msgs))
	var err error
	for m := range msgs {
		plaintexts[m], msgType[m], err = ExtractPlaintext(msgs[m])
		if err != nil {
			return nil, nil, err
		}
	}
	return plaintexts, msgType, nil
}

func ExtractInnerAndTraps(msgs []Message) ([]InnerCiphertext, []Trap, error) {
	var inners []InnerCiphertext
	var traps []Trap
	for m := range msgs {
		// check the last byte of the last msg for the type
		p, err := msgs[m][len(msgs[m])-1].p.Data()
		if err != nil {
			return nil, nil, err
		}
		msgType := p[len(p)-1]

		if msgType == TRAP {
			trap := new(Trap)
			err = trap.UnmarshalBinary(p)
			if err != nil {
				return nil, nil, err
			}
			traps = append(traps, *trap)
		} else {
			c, _, err := ExtractPlaintext(msgs[m][1:])
			if err != nil {
				return nil, nil, err
			}
			inner := InnerCiphertext{
				R: msgs[m][0],
				C: c,
			}
			inners = append(inners, inner)
		}
	}
	return inners, traps, nil
}

func CopyPubs(pubs []*PublicKey) []*PublicKey {
	cp := make([]*PublicKey, len(pubs))
	for i := range pubs {
		b, _ := pubs[i].MarshalBinary()
		cp[i] = new(PublicKey)
		cp[i].UnmarshalBinary(b)
	}
	return cp
}

// randUint64 chooses a uniform random uint64
func randUint64(rand cipher.Stream) uint64 {
	b := random.Bits(64, false, rand)
	return binary.BigEndian.Uint64(b)
}

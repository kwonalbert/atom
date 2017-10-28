package crypto

import (
	"encoding/binary"
	"io"
	"log"

	"golang.org/x/crypto/sha3"
)

type Reader struct {
	io.Reader
}

func NewRandReader(seed []byte) *Reader {
	h := sha3.NewShake128()
	h.Write(seed)
	return &Reader{h}
}

func (r *Reader) UInt() int {
	buf := make([]byte, 8)
	_, err := r.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	tmp, _ := binary.Uvarint(buf)
	return int(tmp)
}

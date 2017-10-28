package server

import (
	"bytes"
	"encoding/binary"

	"golang.org/x/crypto/sha3"

	. "github.com/kwonalbert/atom/crypto"
)

func selectGroup(inner InnerCiphertext, numGroups int) int {
	hash := sha3.Sum256(inner.C)
	var gid uint64
	binary.Read(bytes.NewBuffer(hash[:]), binary.LittleEndian, &gid)
	return int(gid % uint64(numGroups))
}

func memberCommitment(comm Commitment, comms []Commitment) bool {
	for c := range comms {
		if comm == comms[c] {
			return true
		}
	}
	return false
}

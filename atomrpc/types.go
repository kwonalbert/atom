package atomrpc

import . "github.com/kwonalbert/atom/crypto"

type DealArgs struct {
	Uid  int // the unique id of group
	Idx  int
	Deal *ThresholdDeal
}

type DealReply struct {
}

type ResponseArgs struct {
	Uid  int // the unique id of group
	Resp *ThresholdResponse
}

type ResponseReply struct {
}

// basic required info for most rpc calls
type ArgInfo struct {
	Round int
	Level int
	Gid   int
	Cur   int   // an index in the group, NOT server id
	Group []int // list of indices, NOT server ids
}

type SubmitArgs struct {
	Id          int // client id
	Ciphertexts []Ciphertext
	EncProofs   []EncProof
	ArgInfo
}

type SubmitReply struct {
}

type CommitArgs struct {
	Id    int // client id
	Comms []Commitment
	ArgInfo
}

type CommitReply struct {
}

type CollectArgs struct {
	Id          int
	Ciphertexts []Ciphertext
	ArgInfo
}

type CollectReply struct {
}

type ShuffleArgs struct {
	Ciphertexts []Ciphertext
	ArgInfo
}

type VerifyShuffleArgs struct {
	Old   []Ciphertext
	New   []Ciphertext
	Proof ShufProof
	ArgInfo
}

type VerifyShuffleReply struct {
}

type ShuffleReply struct {
}

type ReencryptArgs struct {
	Batches [][]Ciphertext
	ArgInfo
}

type ReencryptReply struct {
}

type VerifyReencryptArgs struct {
	Old    [][]Ciphertext
	New    [][]Ciphertext
	Proofs [][]ReencProof
	ArgInfo
}

type VerifyReencryptReply struct {
}

type ProofOKArgs struct {
	OK bool
	ArgInfo
}

type ProofOKReply struct {
}

type FinalizeArgs struct {
	Plaintexts [][]byte          // used only for verifiable mode
	Inners     []InnerCiphertext // used only for trap mode
	Traps      []Trap
	ArgInfo
}

type FinalizeReply struct {
}

type ReportArgs struct {
	Round        int
	Sid          int
	Uid          int
	CorrectHash  bool
	CorrectTraps bool
	NoDups       bool
	NumTraps     int
	NumMsgs      int
}

type ReportReply struct {
	Priv *PrivateKey
}

type DBArgs struct {
	Round     int
	NumGroups int
	Msgs      [][]byte
}

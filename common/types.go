package common

import (
	"time"

	"github.com/kwonalbert/atom/crypto"
)

// "public randomness"
const SEED_LEN = 16

var SEED = [SEED_LEN]byte{2}

const DEFAULT_TIMEOUT = 5 * time.Second

type SystemParameter struct {
	Mode    int // ver_mode or trap_mode
	NetType int // butterlfy or squareroot

	NumServers  int // total number of servers available
	NumGroups   int // number of groups per level
	PerGroup    int // number of servers per group
	NumTrustees int // number of trsutees in trap mode
	NumLevels   int // number of levels

	NumMsgs int // number of msgs per group
	MsgSize int // number of bytes of plaintext msg

	Threshold int // threshold, if it's used
}

// network nodes
type Group struct {
	Members    []int               // members of the current group (server ids)
	MemberKeys []*crypto.PublicKey // members' long term keys
	GroupKey   *crypto.PublicKey   // final group key
	Level      int                 // current level
	Gid        int                 // gid in the current level
	Uid        int                 // a unique id for this group
	AdjList    []*Group            // adjacency list
}

const (
	VER_MODE  = 0
	TRAP_MODE = 1
)

const (
	BUTTERFLY = 0
	SQUARE    = 1
)

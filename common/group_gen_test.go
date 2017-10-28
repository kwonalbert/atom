package common

import (
	"fmt"
	"testing"

	. "github.com/kwonalbert/atom/crypto"
)

func TestGenerateGroups(t *testing.T) {
	numServers := 32
	numGroups := 32
	perGroup := 32

	_, pubs, _ := GenKeys(numServers)
	groupss := GenerateGroups(SEED, SQUARE, numServers, numGroups,
		perGroup, 10, pubs)
	for level := range groupss {
		for gid := range groupss[level] {
			// add gid above and uncomment below to see the result
			fmt.Println(groupss[level][gid].Members)
		}
	}
}

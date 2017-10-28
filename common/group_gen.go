package common

import (
	"sort"

	. "github.com/kwonalbert/atom/crypto"
)

func GenRandomGroup(numServers, numGroups, perGroup int, rand *Reader) []int {
	group := make([]int, perGroup)
	for s := range group {
		group[s] = -1
	}

	for s := range group {
		for {
			// ensure no duplicate servers in the group
			idx := rand.UInt() % numServers
			if !IsMember(idx, group) {
				group[s] = idx
				break
			}
		}
	}
	return group
}

func GenerateGroups(seed [SEED_LEN]byte, netType,
	numServers, numGroups, perGroup, numLevels int,
	publicKeys []*PublicKey) [][]*Group {
	rand := NewRandReader(seed[:])

	// replicate the groups across levels
	// NOTE: wouldn't replicate it for the throughput maximized version
	baseGroups := make([][]int, numGroups)
	for gid := range baseGroups {
		baseGroups[gid] = GenRandomGroup(numServers, numGroups, perGroup, rand)
		sort.Ints(baseGroups[gid])
		baseGroups[gid] = append(baseGroups[gid][gid%perGroup:],
			baseGroups[gid][:gid%perGroup]...)
	}

	usedUids := make(map[int]bool)

	groupss := make([][]*Group, numLevels)
	for level := range groupss {
		groupss[level] = make([]*Group, numGroups)
		for gid := range groupss[level] {
			members := baseGroups[gid]
			memberKeys := make([]*PublicKey, len(members))
			for m, member := range members {
				memberKeys[m] = publicKeys[member]
			}

			// make sure no duplicate uids
			uid := -1
			for {
				uid = rand.UInt()
				if _, ok := usedUids[uid]; ok {
					continue
				} else {
					usedUids[uid] = true
					break
				}
			}

			groupss[level][gid] = &Group{
				Members:    members,
				MemberKeys: memberKeys,
				Level:      level,
				Gid:        gid,
				Uid:        uid,
				AdjList:    nil,
			}
		}
	}

	if netType == BUTTERFLY {
		//one full butterfly is log of # of groups
		oneButterfly := Log2(numGroups)
		for gid := 0; gid < numGroups; gid++ {
			for level := 0; level < numLevels; level++ {
				// Establish the cross-connections between Shuffle groups
				nextGroup := 0
				// Butterfly connection
				shift := uint(level % oneButterfly)
				if (uint(gid)>>shift)&1 == 0 {
					nextGroup = gid + (1 << shift)
				} else {
					nextGroup = gid - (1 << shift)
				}
				if level < numLevels-1 {
					groupss[level][gid].AdjList =
						[]*Group{groupss[level+1][gid],
							groupss[level+1][nextGroup]}
				} else {
					groupss[level][gid].AdjList =
						[]*Group{nil, nil}
				}
			}
		}
	} else if netType == SQUARE {
		// set to 10 for production
		for level := 0; level < numLevels; level++ {
			for gid := 0; gid < numGroups; gid++ {
				var adjList []*Group = nil
				if level < numLevels-1 {
					adjList = make([]*Group, numGroups)
					for neighbor := range adjList {
						adjList[neighbor] = groupss[level+1][neighbor]
					}
				}
				groupss[level][gid].AdjList = adjList
			}
		}
	}

	return groupss
}

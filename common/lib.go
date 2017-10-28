package common

import (
	"math"
)

// implementes utility and helper functions for atom

func MemberByteSlice(b []byte, bs [][]byte) bool {
	for i := range bs {
		if ByteSliceEqual(b, bs[i]) {
			return true
		}
	}
	return false
}

func ByteSliceEqual(s1, s2 []byte) bool {
	if len(s1) != len(s2) {
		return false
	}
	for s := range s1 {
		if s1[s] != s2[s] {
			return false
		}
	}
	return true
}

func IsMember(val int, set []int) bool {
	for _, v := range set {
		if val == v {
			return true
		}
	}
	return false
}

// log base 2
func Log2(val int) int {
	return int(math.Log2(float64(val)))
}

// Create a range slice
func Xrange(extent int) []int {
	result := make([]int, extent)
	for i := range result {
		result[i] = i
	}
	return result
}

package directory

import (
	"log"
	"net/rpc"

	. "github.com/kwonalbert/atom/common"
	. "github.com/kwonalbert/atom/crypto"
)

func GetDirectory(dirServers []*rpc.Client) (*Directory, SystemParameter, []*PublicKey) {
	// TODO:  actually check consensus
	var res *Directory
	var params SystemParameter
	for _, dirServer := range dirServers {
		var direc Directory
		err := dirServer.Call("DirectoryRPC.Directory", 0, &direc)
		if err != nil {
			log.Fatal("Directory err:", err)
		}
		res = &direc
		params = direc.SystemParameter
	}

	publicKeys := make([]*PublicKey, len(res.Keys))
	for i, pub := range res.Keys {
		publicKeys[i] = LoadPubKey(pub)
	}
	return res, params, publicKeys
}

func GetGroupKeys(dirServers []*rpc.Client) (*Directory, SystemParameter, []*PublicKey, [][]*PublicKey) {
	var res *Directory
	var params SystemParameter

	// TODO:  actually check consensus
	for _, dirServer := range dirServers {

		var direc Directory
		err := dirServer.Call("DirectoryRPC.DirectoryWithGroupKeys", 0, &direc)
		if err != nil {
			log.Fatal("Directory err:", err)
		}

		res = &direc
		params = direc.SystemParameter
	}

	publicKeys := make([]*PublicKey, len(res.Keys))
	for i, pub := range res.Keys {
		publicKeys[i] = LoadPubKey(pub)
	}

	keys := make([][]*PublicKey, len(res.GroupKeys))
	for level := range res.GroupKeys {
		keys[level] = make([]*PublicKey, len(res.GroupKeys[level]))
		for gid := range res.GroupKeys[level] {
			key := LoadPubKey(res.GroupKeys[level][gid])
			keys[level][gid] = key
		}
	}
	return res, params, publicKeys, keys
}

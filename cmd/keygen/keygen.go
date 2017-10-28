package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/kwonalbert/atom/crypto"
)

var (
	serverKeys  = flag.String("serverKeys", "server_keys.json", "Key file")
	trusteeKeys = flag.String("trusteeKeys", "trustee_keys.json", "Key file")
	numServers  = flag.Int("numServers", 0, "# of servers")
	numTrustees = flag.Int("numTrustees", 0, "# of trustees")
)

func main() {
	flag.Parse()

	serverFile, err := os.Create(*serverKeys)
	if err != nil {
		log.Fatal("file err:", err)
	}
	trusteeFile, err := os.Create(*trusteeKeys)
	if err != nil {
		log.Fatal("file err:", err)
	}

	sks := make([]crypto.HexKeyPair, *numServers)
	for s := 0; s < *numServers; s++ {
		key := crypto.GenKey()
		sks[s] = crypto.DumpKey(key)
	}

	tks := make([]crypto.HexKeyPair, *numTrustees)
	for t := 0; t < *numTrustees; t++ {
		key := crypto.GenKey()
		tks[t] = crypto.DumpKey(key)
	}

	sb, err := json.MarshalIndent(sks, "", "  ")
	if err != nil {
		log.Fatal("failed marshaling keys:", err)
	}
	tb, err := json.MarshalIndent(tks, "", "  ")
	if err != nil {
		log.Fatal("failed marshaling keys:", err)
	}

	serverFile.Write(sb)
	trusteeFile.Write(tb)

	serverFile.Close()
	trusteeFile.Close()
}

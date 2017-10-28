package main

import (
	"flag"
	"log"
	"os"

	"github.com/kwonalbert/atom/trustee"
)

var (
	keyFile = flag.String("keyFile", "keys/server_keys.json", "Server key file")
	dirAddr = flag.String("dirAddr", "127.0.0.1:8000", "Directory address")
	addr    = flag.String("addr", "127.0.0.1:8001", "Public address of server")
	id      = flag.Int("id", 0, "Public ID of the server")
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()

	t, err := trustee.NewTrustee(*addr, *id, *keyFile, []string{*dirAddr})
	if err != nil {
		log.Fatal("Trustee err:", err)
	}

	t.Setup()
	t.RegisterRound()

	kill := make(chan os.Signal)
	<-kill
}

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/kwonalbert/atom/server"
)

var (
	keyFile = flag.String("keyFile", "keys/server_keys.json", "Server key file")
	dirAddr = flag.String("dirAddr", "127.0.0.1:8000", "Directory address")
	dbAddr  = flag.String("dbAddr", "127.0.0.1:10001", "Database address")
	addr    = flag.String("addr", "127.0.0.1:8001", "Public address of server")
	id      = flag.Int("id", 0, "Public ID of the server")
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()

	kill := make(chan os.Signal)

	s, err := server.NewServer(*addr, *id, *keyFile, []string{*dirAddr}, *dbAddr)
	if err != nil {
		log.Fatal("Could not start server:", err)
	}

	signal.Notify(kill, syscall.SIGINT, syscall.SIGTERM)

	s.Setup()

	for {
		select {
		case <-kill:
			s.Close()
			os.Exit(0)
		}
	}
}

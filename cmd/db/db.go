package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/kwonalbert/atom/db"
)

var (
	addr = flag.String("dbAddr", "127.0.0.1:10001", "Database address")
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()

	port, err := strconv.Atoi(strings.Split(*addr, ":")[1])
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.NewDB(port)
	if err != nil {
		log.Fatal("Could not start db:", err)
	}

	kill := make(chan os.Signal)
	signal.Notify(kill, syscall.SIGINT, syscall.SIGTERM)
	<-kill
}

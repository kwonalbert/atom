package main

import (
	"flag"
	"log"

	"github.com/kwonalbert/atom/client"
)

var (
	dirAddr = flag.String("dirAddr", "127.0.0.1:8000", "Directory address")
	dbAddr  = flag.String("dbAddr", "127.0.0.1:10001", "Database address")
	id      = flag.Int("id", 0, "Public ID of the client")
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()

	c, err := client.NewClient(*id, []string{*dirAddr}, *dbAddr)
	if err != nil {
		log.Fatal("Could not start client:", err)
	}

	if *id == 0 {
		log.Println("Setting up clients..")
	}
	c.Setup()

	if *id == 0 {
		log.Println("Sending msg")
	}

	c.Submit(*id, 0, c.GenRandPlaintexts())

	if *id == 0 {
		log.Println("Done sending")
	}

	c.DownloadMsgs(0)
}

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	. "github.com/kwonalbert/atom/common"
	"github.com/kwonalbert/atom/directory"
)

var (
	id          = flag.Int("id", 0, "unique id")
	addr        = flag.String("dirAddr", "127.0.0.1:8000", "Directory address")
	perGroup    = flag.Int("perGroup", 1, "# of servers per group")
	numServers  = flag.Int("numServers", 0, "# of servers")
	numClients  = flag.Int("numClients", 0, "# of clients")
	numGroups   = flag.Int("numGroups", 0, "# of groups")
	numTrustees = flag.Int("numTrustees", 0, "# of trustees")
	numMsgs     = flag.Int("numMsgs", 1, "# of msgs per group")
	msgSize     = flag.Int("msgSize", 1, "size of the message in group elements")
	mode        = flag.Int("mode", TRAP_MODE, "Operation mode")
	net         = flag.Int("net", BUTTERFLY, "Network topology")
	branch      = flag.Int("branch", 2, "Branching factor for padding network")
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()

	port, err := strconv.Atoi(strings.Split(*addr, ":")[1])
	if err != nil {
		log.Fatal(err)
	}
	_, err = directory.NewDirectory(*id, port, *mode, *net,
		*numServers, *numGroups, *perGroup, *numTrustees,
		*numMsgs, *msgSize, *perGroup-1,
		*numClients)
	if err != nil {
		log.Fatal("Directory err:", err)
	}

	kill := make(chan os.Signal)
	signal.Notify(kill, syscall.SIGINT, syscall.SIGTERM)
	<-kill
}

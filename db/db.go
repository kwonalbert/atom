package db

// really simple place to gather up the data from all servers

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/rpc"
	"sync"

	"github.com/kwonalbert/atom/atomrpc"
)

type DB struct {
	entries map[int]*entry

	condLock *sync.Mutex
	conds    map[int]*sync.Cond

	listener  net.Listener
	tlsConfig *tls.Config
}

type entry struct {
	numGroups int // number of groups who sent you msg in a round
	msgs      [][]byte
}

func NewDB(port int) (*DB, error) {
	_, tlsConfig := atomrpc.AtomTLSConfig()

	l, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), tlsConfig)
	if err != nil {
		return nil, err
	}

	db := &DB{
		entries: make(map[int]*entry),

		condLock: new(sync.Mutex),
		conds:    make(map[int]*sync.Cond),

		listener:  l,
		tlsConfig: tlsConfig,
	}

	rpcServer := rpc.NewServer()
	rpcServer.Register(db)
	go rpcServer.Accept(l)

	return db, nil
}

// create an entry if it hasn't been created before
func (db *DB) createEntry(round int) {
	db.condLock.Lock()
	defer db.condLock.Unlock()
	if _, ok := db.conds[round]; !ok {
		db.conds[round] = sync.NewCond(new(sync.Mutex))
	}
	if _, ok := db.entries[round]; !ok {
		db.entries[round] = &entry{
			numGroups: 0,
			msgs:      nil,
		}
	}
}

func (db *DB) Write(args *atomrpc.DBArgs, _ *int) error {
	db.createEntry(args.Round)
	db.conds[args.Round].L.Lock()
	entry := db.entries[args.Round]
	entry.msgs = append(entry.msgs, args.Msgs...)
	entry.numGroups++
	if entry.numGroups == args.NumGroups {
		db.conds[args.Round].Broadcast()
	}
	db.conds[args.Round].L.Unlock()
	return nil
}

func (db *DB) Read(args *atomrpc.DBArgs, resp *[][]byte) error {
	db.createEntry(args.Round)
	db.conds[args.Round].L.Lock()
	for db.entries[args.Round].numGroups < args.NumGroups {
		db.conds[args.Round].Wait()
	}
	*resp = db.entries[args.Round].msgs
	db.conds[args.Round].L.Unlock()
	return nil
}

func (db *DB) Close() {
	if db.listener != nil {
		db.listener.Close()
	}
}

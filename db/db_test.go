package db

import (
	"crypto/rand"
	"testing"

	"github.com/kwonalbert/atom/atomrpc"
)

func TestDB(t *testing.T) {
	db, err := NewDB(10001)
	if err != nil {
		t.Error(err)
	}

	res := make(chan [][]byte)
	go func() { // client
		args := atomrpc.DBArgs{
			Round:     0,
			NumGroups: 1,
		}
		var resp [][]byte
		err := db.Read(&args, &resp)
		if err != nil {
			t.Error(err)
		}
		res <- resp
	}()

	msgs := make([][]byte, 64)
	for m := range msgs {
		msgs[m] = make([]byte, 160)
		rand.Read(msgs[m])
	}

	go func(msgs [][]byte) { // server
		args := atomrpc.DBArgs{
			Round:     0,
			NumGroups: 1,
			Msgs:      msgs,
		}
		err := db.Write(&args, nil)
		if err != nil {
			t.Error(err)
		}
	}(msgs)

	result := <-res
	for r := range result {
		for i := range result[r] {
			if msgs[r][i] != result[r][i] {
				t.Error("Msg mismatch")
			}
		}
	}
}

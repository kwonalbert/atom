package atomrpc

import (
	"net/rpc"
	"time"
)

type AtomRPCError struct {
	error
	err     string
	timeout bool
}

func (e *AtomRPCError) Error() string {
	return e.err
}

func (e *AtomRPCError) Timeout() bool {
	return e.timeout
}

// RPC with timeout
func AtomRPC(client *rpc.Client, method string, args interface{}, reply interface{}, timeout time.Duration) error {
	done := make(chan *rpc.Call, 1)
	client.Go(method, args, reply, done)
	select {
	case res := <-done:
		if res.Error != nil {
			return res.Error
		} else {
			return nil
		}
	case <-time.After(timeout):
		return &AtomRPCError{err: "Timeout", timeout: true}
	}
}

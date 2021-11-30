package gomsf

import "github.com/hupe1980/gomsf/rpc"

type CoreManager struct {
	rpc *rpc.RPC
}

func (c *CoreManager) Version() (*rpc.CoreVersionRes, error) {
	return c.rpc.Core.Version()
}

package gomsf

import (
	"errors"

	"github.com/hupe1980/gomsf/rpc"
)

type CoreManager struct {
	rpc *rpc.RPC
}

func (c *CoreManager) Version() (*rpc.CoreVersionRes, error) {
	return c.rpc.Core.Version()
}

// Stop stops the core
func (c *CoreManager) Stop() error {
	r, err := c.rpc.Core.Stop()
	if err != nil {
		return err
	}

	if r.Result == rpc.FAILURE {
		return errors.New("cannot stop the core")
	}

	return nil
}

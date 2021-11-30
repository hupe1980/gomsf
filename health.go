package gomsf

import "github.com/hupe1980/gomsf/rpc"

type HealthManager struct {
	rpc *rpc.RPC
}

func (hm *HealthManager) Check() error {
	return hm.rpc.Health.Check()
}

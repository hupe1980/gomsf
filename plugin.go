package gomsf

import (
	"fmt"

	"github.com/hupe1980/gomsf/rpc"
)

type PluginManager struct {
	rpc *rpc.RPC
}

func (pm *PluginManager) List() ([]string, error) {
	r, err := pm.rpc.Plugin.Loaded()
	if err != nil {
		return nil, err
	}

	return r.Plugins, nil
}

func (pm *PluginManager) Load(name string, options map[string]string) error {
	r, err := pm.rpc.Plugin.Load(name, options)
	if err != nil {
		return err
	}

	if r.Result == rpc.FAILURE {
		return fmt.Errorf("cannot load plugin %s", name)
	}

	return nil
}

func (pm *PluginManager) UnLoad(name string) error {
	r, err := pm.rpc.Plugin.UnLoad(name)
	if err != nil {
		return err
	}

	if r.Result == rpc.FAILURE {
		return fmt.Errorf("cannot unload plugin %s", name)
	}

	return nil
}

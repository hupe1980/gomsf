package gomsf

import (
	"fmt"
	"reflect"
)

type coreAddModulePathReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
	Path     string
}

type coreAddModulePathRes struct {
	Exploits  uint32 `msgpack:"exploits"`
	Auxiliary uint32 `msgpack:"auxiliary"`
	Post      uint32 `msgpack:"post"`
	Encoders  uint32 `msgpack:"encoders"`
	Nops      uint32 `msgpack:"nops"`
	Payloads  uint32 `msgpack:"payloads"`
}

// CoreAddModulePath adds a new local file system path (local to the server) as a module path
func (c *Client) CoreAddModulePath(path string) (*coreAddModulePathRes, error) {
	req := &coreAddModulePathReq{
		Method: "core.add_module_path",
		Token:  c.token,
		Path:   path,
	}

	var res *coreAddModulePathRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type coreGetgReq struct {
	_msgpack   struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method     string
	Token      string
	OptionName string
}

type coreGetgRes struct {
	Result string
}

// CoreGetg returns a global datastore option
func (c *Client) CoreGetg(optionName string) (*coreGetgRes, error) {
	req := &coreGetgReq{
		Method:     "core.getg",
		Token:      c.token,
		OptionName: optionName,
	}

	var res interface{}
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return &coreGetgRes{Result: fmt.Sprintf("%s", reflect.ValueOf(res).MapIndex(reflect.ValueOf(optionName)))}, nil
}

type coreModuleStatsReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
}

type coreModuleStatsRes struct {
	Exploits  uint32 `msgpack:"exploits"`
	Auxiliary uint32 `msgpack:"auxiliary"`
	Post      uint32 `msgpack:"post"`
	Encoders  uint32 `msgpack:"encoders"`
	Nops      uint32 `msgpack:"nops"`
	Payloads  uint32 `msgpack:"payloads"`
}

// CoreModuleStats returns the module stats
func (c *Client) CoreModuleStats() (*coreModuleStatsRes, error) {
	req := &coreModuleStatsReq{
		Method: "core.module_stats",
		Token:  c.token,
	}

	var res *coreModuleStatsRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type coreReloadModulesReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
}

type coreReloadModulesRes struct {
	Exploits  uint32 `msgpack:"exploits"`
	Auxiliary uint32 `msgpack:"auxiliary"`
	Post      uint32 `msgpack:"post"`
	Encoders  uint32 `msgpack:"encoders"`
	Nops      uint32 `msgpack:"nops"`
	Payloads  uint32 `msgpack:"payloads"`
}

// CoreReloadModules reloads framework modules
func (c *Client) CoreReloadModules() (*coreReloadModulesRes, error) {
	req := &coreReloadModulesReq{
		Method: "core.reload_modules",
		Token:  c.token,
	}

	var res *coreReloadModulesRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type coreSaveReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
}

type coreSaveRes struct {
	Result string `msgpack:"result"`
}

// CoreSave saves current framework settings
func (c *Client) CoreSave() (*coreSaveRes, error) {
	req := &coreSaveReq{
		Method: "core.save",
		Token:  c.token,
	}

	var res *coreSaveRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type coreSetgReq struct {
	_msgpack    struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method      string
	Token       string
	OptionName  string
	OptionValue string
}

type coreSetgRes struct {
	Result string `msgpack:"result"`
}

// CoreSetg sets a global datastore option
func (c *Client) CoreSetg(optionName, optionValue string) (*coreSetgRes, error) {
	req := &coreSetgReq{
		Method:      "core.setg",
		Token:       c.token,
		OptionName:  optionName,
		OptionValue: optionValue,
	}

	var res *coreSetgRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type coreStopReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
}

type coreStopRes struct {
	Result string `msgpack:"result"`
}

// CoreStop stops the RPC service
func (c *Client) CoreStop() (*coreStopRes, error) {
	req := &coreStopReq{
		Method: "core.stop",
		Token:  c.token,
	}
	var res *coreStopRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type coreThreadKillReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
	ThreadId string
}

type coreThreadKillRes struct {
	Result string `msgpack:"result"`
}

// CoreThreadKill kills a framework thread
func (c *Client) CoreThreadKill(threadId string) (*coreThreadKillRes, error) {
	req := &coreThreadKillReq{
		Method:   "core.thread_kill",
		Token:    c.token,
		ThreadId: threadId,
	}

	var res *coreThreadKillRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type coreThreadListReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
}

type coreThreadListRes map[int]struct {
	Status   string `msgpack:"status"`
	Critical bool   `msgpack:"critical"`
	Name     string `msgpack:"name"`
	Started  string `msgpack:"started"`
}

// CoreThreadList returns a list of framework threads
func (c *Client) CoreThreadList() (*coreThreadListRes, error) {
	req := &coreThreadListReq{
		Method: "core.thread_list",
		Token:  c.token,
	}

	var res *coreThreadListRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type coreUnsetgReq struct {
	_msgpack   struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method     string
	Token      string
	OptionName string
}

type coreUnsetgRes struct {
	Result string `msgpack:"result"`
}

// CoreUnsetg unsets a global datastore option
func (c *Client) CoreUnsetg(optionName string) (*coreUnsetgRes, error) {
	req := &coreUnsetgReq{
		Method:     "core.unsetg",
		Token:      c.token,
		OptionName: optionName,
	}

	var res *coreUnsetgRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type coreVersionReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
}

type coreVersionRes struct {
	Version string `msgpack:"version"` // Framework version
	Ruby    string `msgpack:"ruby"`    // Ruby version
	Api     string `msgpack:"api"`     // API version
}

// CoreVersion returns the RPC service versions
func (c *Client) CoreVersion() (*coreVersionRes, error) {
	req := &coreVersionReq{
		Method: "core.version",
		Token:  c.token,
	}
	var res *coreVersionRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

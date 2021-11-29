package gomsf

import (
	"reflect"
)

type CoreAddModulePathReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
	Path     string
}

type CoreAddModulePathRes struct {
	Exploits  uint32 `msgpack:"exploits"`
	Auxiliary uint32 `msgpack:"auxiliary"`
	Post      uint32 `msgpack:"post"`
	Encoders  uint32 `msgpack:"encoders"`
	Nops      uint32 `msgpack:"nops"`
	Payloads  uint32 `msgpack:"payloads"`
}

// CoreAddModulePath adds a new local file system path (local to the server) as a module path
func (c *Client) CoreAddModulePath(path string) (*CoreAddModulePathRes, error) {
	req := &CoreAddModulePathReq{
		Method: "core.add_module_path",
		Token:  c.token,
		Path:   path,
	}

	var res *CoreAddModulePathRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type CoreGetgReq struct {
	_msgpack   struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method     string
	Token      string
	OptionName string
}

type CoreGetgRes struct {
	Result string
}

// CoreGetg returns a global datastore option
func (c *Client) CoreGetg(optionName string) (*CoreGetgRes, error) {
	req := &CoreGetgReq{
		Method:     "core.getg",
		Token:      c.token,
		OptionName: optionName,
	}

	var res interface{}
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return &CoreGetgRes{Result: reflect.ValueOf(res).MapIndex(reflect.ValueOf(optionName)).String()}, nil
}

type CoreModuleStatsReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
}

type CoreModuleStatsRes struct {
	Exploits  uint32 `msgpack:"exploits"`
	Auxiliary uint32 `msgpack:"auxiliary"`
	Post      uint32 `msgpack:"post"`
	Encoders  uint32 `msgpack:"encoders"`
	Nops      uint32 `msgpack:"nops"`
	Payloads  uint32 `msgpack:"payloads"`
}

// CoreModuleStats returns the module stats
func (c *Client) CoreModuleStats() (*CoreModuleStatsRes, error) {
	req := &CoreModuleStatsReq{
		Method: "core.module_stats",
		Token:  c.token,
	}

	var res *CoreModuleStatsRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type CoreReloadModulesReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
}

type CoreReloadModulesRes struct {
	Exploits  uint32 `msgpack:"exploits"`
	Auxiliary uint32 `msgpack:"auxiliary"`
	Post      uint32 `msgpack:"post"`
	Encoders  uint32 `msgpack:"encoders"`
	Nops      uint32 `msgpack:"nops"`
	Payloads  uint32 `msgpack:"payloads"`
}

// CoreReloadModules reloads framework modules
func (c *Client) CoreReloadModules() (*CoreReloadModulesRes, error) {
	req := &CoreReloadModulesReq{
		Method: "core.reload_modules",
		Token:  c.token,
	}

	var res *CoreReloadModulesRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type CoreSaveReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
}

type CoreSaveRes struct {
	Result string `msgpack:"result"`
}

// CoreSave saves current framework settings
func (c *Client) CoreSave() (*CoreSaveRes, error) {
	req := &CoreSaveReq{
		Method: "core.save",
		Token:  c.token,
	}

	var res *CoreSaveRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type CoreSetgReq struct {
	_msgpack    struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method      string
	Token       string
	OptionName  string
	OptionValue string
}

type CoreSetgRes struct {
	Result string `msgpack:"result"`
}

// CoreSetg sets a global datastore option
func (c *Client) CoreSetg(optionName, optionValue string) (*CoreSetgRes, error) {
	req := &CoreSetgReq{
		Method:      "core.setg",
		Token:       c.token,
		OptionName:  optionName,
		OptionValue: optionValue,
	}

	var res *CoreSetgRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type CoreStopReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
}

type CoreStopRes struct {
	Result string `msgpack:"result"`
}

// CoreStop stops the RPC service
func (c *Client) CoreStop() (*CoreStopRes, error) {
	req := &CoreStopReq{
		Method: "core.stop",
		Token:  c.token,
	}

	var res *CoreStopRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type CoreThreadKillReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
	ThreadID string
}

type CoreThreadKillRes struct {
	Result string `msgpack:"result"`
}

// CoreThreadKill kills a framework thread
func (c *Client) CoreThreadKill(threadID string) (*CoreThreadKillRes, error) {
	req := &CoreThreadKillReq{
		Method:   "core.thread_kill",
		Token:    c.token,
		ThreadID: threadID,
	}

	var res *CoreThreadKillRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type CoreThreadListReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
}

type CoreThreadListRes map[int]struct {
	Status   string `msgpack:"status"`
	Critical bool   `msgpack:"critical"`
	Name     string `msgpack:"name"`
	Started  string `msgpack:"started"`
}

// CoreThreadList returns a list of framework threads
func (c *Client) CoreThreadList() (*CoreThreadListRes, error) {
	req := &CoreThreadListReq{
		Method: "core.thread_list",
		Token:  c.token,
	}

	var res *CoreThreadListRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type CoreUnsetgReq struct {
	_msgpack   struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method     string
	Token      string
	OptionName string
}

type CoreUnsetgRes struct {
	Result string `msgpack:"result"`
}

// CoreUnsetg unsets a global datastore option
func (c *Client) CoreUnsetg(optionName string) (*CoreUnsetgRes, error) {
	req := &CoreUnsetgReq{
		Method:     "core.unsetg",
		Token:      c.token,
		OptionName: optionName,
	}

	var res *CoreUnsetgRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type CoreVersionReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
}

type CoreVersionRes struct {
	Version string `msgpack:"version"` // Framework version
	Ruby    string `msgpack:"ruby"`    // Ruby version
	API     string `msgpack:"api"`     // API version
}

// CoreVersion returns the RPC service versions
func (c *Client) CoreVersion() (*CoreVersionRes, error) {
	req := &CoreVersionReq{
		Method: "core.version",
		Token:  c.token,
	}

	var res *CoreVersionRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

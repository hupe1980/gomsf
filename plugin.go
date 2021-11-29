package gomsf

type PluginLoadReq struct {
	_msgpack   struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method     string
	Token      string
	PluginName string
	Options    map[string]string
}

type PluginLoadRes struct {
	Result string `msgpack:"result"`
}

// PluginLoad loads a plugin
func (c *Client) PluginLoad(pluginName string, pluginOptions map[string]string) (*PluginLoadRes, error) {
	req := &PluginLoadReq{
		Method:     "plugin.load",
		Token:      c.token,
		PluginName: pluginName,
		Options:    pluginOptions,
	}

	var res *PluginLoadRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type PluginLoadedReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
}

type PluginLoadedRes struct {
	Plugins []string `msgpack:"plugins"`
}

// PluginLoaded returns a list of loaded plugins
func (c *Client) PluginLoaded() (*PluginLoadedRes, error) {
	req := &PluginLoadedReq{
		Method: "plugin.loaded",
		Token:  c.token,
	}

	var res *PluginLoadedRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type PluginUnLoadReq struct {
	_msgpack   struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method     string
	Token      string
	PluginName string
}

type PluginUnLoadRes struct {
	Result string `msgpack:"result"`
}

// PluginUnload unloads a plugin
func (c *Client) PluginUnLoad(pluginName string) (*PluginUnLoadRes, error) {
	req := &PluginUnLoadReq{
		Method:     "plugin.unload",
		Token:      c.token,
		PluginName: pluginName,
	}

	var res *PluginUnLoadRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

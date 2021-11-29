package gomsf

type pluginLoadReq struct {
	_msgpack   struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method     string
	Token      string
	PluginName string
	Options    map[string]string
}

type pluginLoadRes struct {
	Result string `msgpack:"result"`
}

// PluginLoad loads a plugin
func (c *Client) PluginLoad(pluginName string, pluginOptions map[string]string) (*pluginLoadRes, error) {
	req := &pluginLoadReq{
		Method:     "plugin.load",
		Token:      c.token,
		PluginName: pluginName,
		Options:    pluginOptions,
	}
	var res *pluginLoadRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type pluginLoadedReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
}

type pluginLoadedRes struct {
	Plugins []string `msgpack:"plugins"`
}

// PluginLoaded returns a list of loaded plugins
func (c *Client) PluginLoaded() (*pluginLoadedRes, error) {
	req := &pluginLoadedReq{
		Method: "plugin.loaded",
		Token:  c.token,
	}
	var res *pluginLoadedRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type pluginUnLoadReq struct {
	_msgpack   struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method     string
	Token      string
	PluginName string
}

type pluginUnLoadRes struct {
	Result string `msgpack:"result"`
}

// PluginUnload unloads a plugin
func (c *Client) PluginUnLoad(pluginName string) (*pluginUnLoadRes, error) {
	req := &pluginUnLoadReq{
		Method:     "plugin.unload",
		Token:      c.token,
		PluginName: pluginName,
	}
	var res *pluginUnLoadRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

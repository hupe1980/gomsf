package gomsf

type consoleCreateReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
}

type consoleCreateRes struct {
	Id     string `msgpack:"id"`
	Prompt string `msgpack:"prompt"`
	Busy   bool   `msgpack:"busy"`
}

// ConsoleCreate creates a new framework console instance
func (c *Client) ConsoleCreate() (*consoleCreateRes, error) {
	req := &consoleCreateReq{
		Method: "console.create",
		Token:  c.token,
	}
	var res *consoleCreateRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type consoleDestroyReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method    string
	Token     string
	ConsoleId string
}

type consoleDestroyRes struct {
	Result string `msgpack:"result"`
}

// ConsoleDestroy deletes a framework console instance
func (c *Client) ConsoleDestroy(consoleid string) (*consoleDestroyRes, error) {
	req := &consoleDestroyReq{
		Method:    "console.destroy",
		Token:     c.token,
		ConsoleId: consoleid,
	}
	var res *consoleDestroyRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type consoleListReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
}

type consoleListRes map[string][]struct {
	Id     string `msgpack:"id"`
	Prompt string `msgpack:"prompt"`
	Busy   bool   `msgpack:"busy"`
}

// ConsoleList returns a list of framework consoles
func (c *Client) ConsoleList() (*consoleListRes, error) {
	req := &consoleListReq{
		Method: "console.list",
		Token:  c.token,
	}
	var res *consoleListRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type consoleReadReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method    string
	Token     string
	ConsoleId string
}

type consoleReadRes struct {
	Data   string `msgpack:"data"`
	Prompt string `msgpack:"prompt"`
	Busy   bool   `msgpack:"busy"`
}

// ConsoleRead returns the framework console output in raw form
func (c *Client) ConsoleRead(consoleId string) (*consoleReadRes, error) {
	req := &consoleReadReq{
		Method:    "console.read",
		Token:     c.token,
		ConsoleId: consoleId,
	}
	var res *consoleReadRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type consoleSessionDetachReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method    string
	Token     string
	ConsoleId string
}

type consoleSessionDetachRes struct {
	Result string `msgpack:"result"`
}

// ConsoleSessionDetach detaches a framework session
func (c *Client) ConsoleSessionDetach(consoleId string) (*consoleSessionDetachRes, error) {
	req := &consoleSessionDetachReq{
		Method:    "console.session_detach",
		Token:     c.token,
		ConsoleId: consoleId,
	}
	var res *consoleSessionDetachRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type consoleSessionKillReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method    string
	Token     string
	ConsoleId string
}

type consoleSessionKillRes struct {
	Result string `msgpack:"result"`
}

// ConsoleSessionKill kills a framework session
func (c *Client) ConsoleSessionKill(consoleId string) (*consoleSessionKillRes, error) {
	req := &consoleSessionKillReq{
		Method:    "console.session_kill",
		Token:     c.token,
		ConsoleId: consoleId,
	}
	var res *consoleSessionKillRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type consoleTabsReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method    string
	Token     string
	ConsoleId string
	InputLine string
}

type consoleTabsRes struct {
	Tabs []string `msgpack:"tabs"`
}

// ConsoleTabs returns the tab-completed version of your input (such as a module path)
func (c *Client) ConsoleTabs(consoleId, inputLine string) (*consoleTabsRes, error) {
	req := &consoleTabsReq{
		Method:    "console.tabs",
		Token:     c.token,
		ConsoleId: consoleId,
		InputLine: inputLine,
	}
	var res *consoleTabsRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type consoleWriteReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method    string
	Token     string
	ConsoleId string
	Command   string
}

type consoleWriteRes struct {
	Wrote uint32 `msgpack:"wrote"`
}

// ConsoleWrite sends an input (such as a command) to the framework console
func (c *Client) ConsoleWrite(consoleId, command string) (*consoleWriteRes, error) {
	req := &consoleWriteReq{
		Method:    "console.write",
		Token:     c.token,
		ConsoleId: consoleId,
		Command:   command,
	}
	var res *consoleWriteRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

package gomsf

type ConsoleCreateReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
}

type ConsoleCreateRes struct {
	ID     string `msgpack:"id"`
	Prompt string `msgpack:"prompt"`
	Busy   bool   `msgpack:"busy"`
}

// ConsoleCreate creates a new framework console instance
func (c *Client) ConsoleCreate() (*ConsoleCreateRes, error) {
	req := &ConsoleCreateReq{
		Method: "console.create",
		Token:  c.token,
	}

	var res *ConsoleCreateRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ConsoleDestroyReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method    string
	Token     string
	ConsoleID string
}

type ConsoleDestroyRes struct {
	Result string `msgpack:"result"`
}

// ConsoleDestroy deletes a framework console instance
func (c *Client) ConsoleDestroy(consoleID string) (*ConsoleDestroyRes, error) {
	req := &ConsoleDestroyReq{
		Method:    "console.destroy",
		Token:     c.token,
		ConsoleID: consoleID,
	}

	var res *ConsoleDestroyRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ConsoleListReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
}

type ConsoleListRes map[string][]struct {
	ID     string `msgpack:"id"`
	Prompt string `msgpack:"prompt"`
	Busy   bool   `msgpack:"busy"`
}

// ConsoleList returns a list of framework consoles
func (c *Client) ConsoleList() (*ConsoleListRes, error) {
	req := &ConsoleListReq{
		Method: "console.list",
		Token:  c.token,
	}

	var res *ConsoleListRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ConsoleReadReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method    string
	Token     string
	ConsoleID string
}

type ConsoleReadRes struct {
	Data   string `msgpack:"data"`
	Prompt string `msgpack:"prompt"`
	Busy   bool   `msgpack:"busy"`
}

// ConsoleRead returns the framework console output in raw form
func (c *Client) ConsoleRead(consoleID string) (*ConsoleReadRes, error) {
	req := &ConsoleReadReq{
		Method:    "console.read",
		Token:     c.token,
		ConsoleID: consoleID,
	}

	var res *ConsoleReadRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ConsoleSessionDetachReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method    string
	Token     string
	ConsoleID string
}

type ConsoleSessionDetachRes struct {
	Result string `msgpack:"result"`
}

// ConsoleSessionDetach detaches a framework session
func (c *Client) ConsoleSessionDetach(consoleID string) (*ConsoleSessionDetachRes, error) {
	req := &ConsoleSessionDetachReq{
		Method:    "console.session_detach",
		Token:     c.token,
		ConsoleID: consoleID,
	}

	var res *ConsoleSessionDetachRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ConsoleSessionKillReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method    string
	Token     string
	ConsoleID string
}

type ConsoleSessionKillRes struct {
	Result string `msgpack:"result"`
}

// ConsoleSessionKill kills a framework session
func (c *Client) ConsoleSessionKill(consoleID string) (*ConsoleSessionKillRes, error) {
	req := &ConsoleSessionKillReq{
		Method:    "console.session_kill",
		Token:     c.token,
		ConsoleID: consoleID,
	}

	var res *ConsoleSessionKillRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ConsoleTabsReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method    string
	Token     string
	ConsoleID string
	InputLine string
}

type ConsoleTabsRes struct {
	Tabs []string `msgpack:"tabs"`
}

// ConsoleTabs returns the tab-completed version of your input (such as a module path)
func (c *Client) ConsoleTabs(consoleID, inputLine string) (*ConsoleTabsRes, error) {
	req := &ConsoleTabsReq{
		Method:    "console.tabs",
		Token:     c.token,
		ConsoleID: consoleID,
		InputLine: inputLine,
	}

	var res *ConsoleTabsRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ConsoleWriteReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method    string
	Token     string
	ConsoleID string
	Command   string
}

type ConsoleWriteRes struct {
	Wrote uint32 `msgpack:"wrote"`
}

// ConsoleWrite sends an input (such as a command) to the framework console
func (c *Client) ConsoleWrite(consoleID, command string) (*ConsoleWriteRes, error) {
	req := &ConsoleWriteReq{
		Method:    "console.write",
		Token:     c.token,
		ConsoleID: consoleID,
		Command:   command,
	}

	var res *ConsoleWriteRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

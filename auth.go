package gomsf

import "errors"

type loginReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Username string // The username
	Password string // The password
}

type loginRes struct {
	Result string `msgpack:"result"`
	Token  string `msgpack:"token"`
}

// Login logs in by calling the 'auth.login' API. The authentication token will expire after 5
// minutes, but will automatically be rewnewed when you make a new RPC request.
func (c *Client) Login(user, pass string) error {
	req := &loginReq{
		Method:   "auth.login",
		Username: user,
		Password: pass,
	}

	var res *loginRes
	if err := c.call(req, &res); err != nil {
		return err
	}
	if res.Result != "success" || res.Token == "" {
		return errors.New("authentication failed")
	}

	c.user = user
	c.pass = pass
	c.token = res.Token

	return nil
}

// ReLogin attempts to login again with the last known user name and password
func (c *Client) ReLogin() error {
	return c.Login(c.user, c.pass)
}

type logoutReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
}

type logoutRes struct {
	Result string `msgpack:"result"`
}

func (c *Client) Logout() error {
	req := &logoutReq{
		Method: "auth.logout",
		Token:  c.token,
	}

	var res *logoutRes
	if err := c.call(req, res); err != nil {
		return err
	}

	c.user = ""
	c.pass = ""
	c.token = ""

	return nil
}

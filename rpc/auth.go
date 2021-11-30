package rpc

type auth struct {
	client Client
}

type AuthLoginReq struct {
	Method   string
	Username string // The username
	Password string // The password
}

type AuthLoginRes struct {
	Result Result `msgpack:"result"`
	Token  string `msgpack:"token"`
}

// Login handles client authentication
func (a *auth) Login(user, pass string) (*AuthLoginRes, error) {
	req := &AuthLoginReq{
		Method:   "auth.login",
		Username: user,
		Password: pass,
	}

	var res *AuthLoginRes
	if err := a.client.Call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type AuthLogoutReq struct {
	Method string
	Token  string
}

type AuthLogoutRes struct {
	Result Result `msgpack:"result"`
}

// Logout handles client deauthentication
func (a *auth) Logout() (*AuthLogoutRes, error) {
	req := &AuthLogoutReq{
		Method: "auth.logout",
		Token:  a.client.Token(),
	}

	var res *AuthLogoutRes
	if err := a.client.Call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

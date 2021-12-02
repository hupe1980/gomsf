package rpc

type auth struct {
	rpc *RPC
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
	if err := a.rpc.Call(req, &res); err != nil {
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
		Token:  a.rpc.Token(),
	}

	var res *AuthLogoutRes
	if err := a.rpc.Call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type AuthTokenListReq struct {
	Method string
	Token  string
}

type AuthTokenListRes struct {
	Tokens []string `msgpack:"tokens"`
}

// TokenList returns a list of authentication tokens, including the ones that are temporary, permanent, or stored in the backend
func (m *module) TokenList(moduleName string, target int) (*AuthTokenListRes, error) {
	req := &AuthTokenListReq{
		Method: "auth.token_list",
		Token:  m.rpc.Token(),
	}

	var res *AuthTokenListRes
	if err := m.rpc.Call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

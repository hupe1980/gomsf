package gomsf

type SessionMeterpreterWriteReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method    string
	Token     string
	SessionID uint32
	Command   string
}

type SessionMeterpreterWriteRes struct {
	Result string `msgpack:"result"`
}

type SessionMeterpreterReadReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method    string
	Token     string
	SessionID uint32
}

type SessionMeterpreterReadRes struct {
	Data string `msgpack:"data"`
}

type SessionMeterpreterRunSingleReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method    string
	Token     string
	SessionID uint32
	Command   string
}

type SessionMeterpreterRunSingleRes SessionMeterpreterWriteRes

type SessionMeterpreterDetachReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method    string
	Token     string
	SessionID uint32
}

type SessionMeterpreterDetachRes SessionMeterpreterWriteRes

type SessionMeterpreterKillReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method    string
	Token     string
	SessionID uint32
}

type SessionMeterpreterKillRes SessionMeterpreterWriteRes

type SessionCompatibleModulesReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method    string
	Token     string
	SessionID uint32
}

type SessionCompatibleModulesRes struct {
	Modules []string `msgpack:"modules"`
}

type SessionShellUpgradeReq struct {
	_msgpack   struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method     string
	Token      string
	SessionID  uint32
	IPAddress  string
	PortNumber uint32
}

type SessionShellUpgradeRes SessionMeterpreterWriteRes

type SessionRingClearReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method    string
	Token     string
	SessionID uint32
}

type SessionRingClearRes SessionMeterpreterWriteRes

type SessionRingPutReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method    string
	Token     string
	SessionID uint32
	Command   string
}

type SessionRingPutRes struct {
	WriteCount uint32 `msgpack:"write_count"`
}

type SessionListReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
}

type SessionListRes map[uint32]struct {
	Type        string `msgpack:"type"`
	TunnelLocal string `msgpack:"tunnel_local"`
	TunnelPeer  string `msgpack:"tunnel_peer"`
	ViaExploit  string `msgpack:"via_exploit"`
	ViaPayload  string `msgpack:"via_payload"`
	Description string `msgpack:"desc"`
	Info        string `msgpack:"info"`
	Workspace   string `msgpack:"workspace"`
	SessionHost string `msgpack:"session_host"`
	SessionPort int    `msgpack:"session_port"`
	Username    string `msgpack:"username"`
	UUID        string `msgpack:"uuid"`
	ExploitUUID string `msgpack:"exploit_uuid"`
}

func (c *Client) SessionList() (SessionListRes, error) {
	req := &SessionListReq{
		Method: "session.list",
		Token:  c.token,
	}

	var res SessionListRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type SessionShellWriteReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method    string
	Token     string
	SessionID uint32
	Command   string
}

type SessionShellWriteRes struct {
	WriteCount string `msgpack:"write_count"`
}

func (c *Client) SessionShellWrite(session uint32, command string) error {
	req := &SessionShellWriteReq{
		Method:    "session.shell_write",
		Token:     c.token,
		SessionID: session,
		Command:   command,
	}

	var res SessionShellWriteRes
	if err := c.call(req, &res); err != nil {
		return err
	}

	return nil
}

type SessionShellReadReq struct {
	_msgpack    struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method      string
	Token       string
	SessionID   uint32
	ReadPointer uint32
}

type SessionShellReadRes struct {
	Seq  uint32 `msgpack:"seq"`
	Data string `msgpack:"data"`
}

func (c *Client) SessionShellRead(session, readPointer uint32) (string, error) {
	req := &SessionShellReadReq{
		Method:      "session.shell_read",
		Token:       c.token,
		SessionID:   session,
		ReadPointer: readPointer,
	}

	var res SessionShellReadRes
	if err := c.call(req, &res); err != nil {
		return "", err
	}

	return res.Data, nil
}

func (c *Client) SessionMeterpreterWrite(session uint32, command string) (SessionMeterpreterWriteRes, error) {
	req := &SessionMeterpreterWriteReq{
		Method:    "session.meterpreter_write",
		Token:     c.token,
		SessionID: session,
		Command:   command,
	}

	var res SessionMeterpreterWriteRes
	if err := c.call(req, &res); err != nil {
		return SessionMeterpreterWriteRes{}, err
	}

	return res, nil
}

func (c *Client) SessionMeterpreterRead(session uint32) (SessionMeterpreterReadRes, error) {
	req := &SessionMeterpreterReadReq{
		Method:    "session.meterpreter_read",
		Token:     c.token,
		SessionID: session,
	}

	var res SessionMeterpreterReadRes
	if err := c.call(req, &res); err != nil {
		return SessionMeterpreterReadRes{}, err
	}

	return res, nil
}

func (c *Client) SessionMeterpreterRunSingle(session uint32, command string) (SessionMeterpreterRunSingleRes, error) {
	req := &SessionMeterpreterRunSingleReq{
		Method:    "session.meterpreter_run_single",
		Token:     c.token,
		SessionID: session,
		Command:   command,
	}

	var res SessionMeterpreterRunSingleRes
	if err := c.call(req, &res); err != nil {
		return SessionMeterpreterRunSingleRes{}, err
	}

	return res, nil
}

func (c *Client) SessionMeterpreterSessionDetach(session uint32) (SessionMeterpreterDetachRes, error) {
	req := &SessionMeterpreterDetachReq{
		Method:    "session.meterpreter_session_detach",
		Token:     c.token,
		SessionID: session,
	}

	var res SessionMeterpreterDetachRes
	if err := c.call(req, &res); err != nil {
		return SessionMeterpreterDetachRes{}, err
	}

	return res, nil
}

func (c *Client) SessionMeterpreterSessionKill(session uint32) (SessionMeterpreterKillRes, error) {
	req := &SessionMeterpreterKillReq{
		Method:    "session.meterpreter_session_kill",
		Token:     c.token,
		SessionID: session,
	}

	var res SessionMeterpreterKillRes
	if err := c.call(req, &res); err != nil {
		return SessionMeterpreterKillRes{}, err
	}

	return res, nil
}

type SessionMeterpreterTabsReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method    string
	Token     string
	SessionID uint32
	InputLine string
}

type SessionMeterpreterTabsRes struct {
	Tabs []string `msgpack:"tabs"`
}

func (c *Client) SessionMeterpreterTabs(session uint32, inputLine string) (SessionMeterpreterTabsRes, error) {
	req := &SessionMeterpreterTabsReq{
		Method:    "session.meterpreter_tabs",
		Token:     c.token,
		SessionID: session,
		InputLine: inputLine,
	}

	var res SessionMeterpreterTabsRes
	if err := c.call(req, &res); err != nil {
		return SessionMeterpreterTabsRes{}, err
	}

	return res, nil
}

func (c *Client) SessionCompatibleModules(session uint32) (SessionCompatibleModulesRes, error) {
	req := &SessionCompatibleModulesReq{
		Method:    "session.compatible_modules",
		Token:     c.token,
		SessionID: session,
	}

	var res SessionCompatibleModulesRes
	if err := c.call(req, &res); err != nil {
		return SessionCompatibleModulesRes{}, err
	}

	return res, nil
}

func (c *Client) SessionShellUpgrade(session uint32, lhostAddress string, lportNumber uint32) (SessionShellUpgradeRes, error) {
	req := &SessionShellUpgradeReq{
		Method:     "session.shell_upgrade",
		Token:      c.token,
		SessionID:  session,
		IPAddress:  lhostAddress,
		PortNumber: lportNumber,
	}

	var res SessionShellUpgradeRes
	if err := c.call(req, &res); err != nil {
		return SessionShellUpgradeRes{}, err
	}

	return res, nil
}

func (c *Client) SessionRingClear(session uint32) (SessionRingClearRes, error) {
	req := &SessionRingClearReq{
		Method:    "session.ring_clear",
		Token:     c.token,
		SessionID: session,
	}

	var res SessionRingClearRes
	if err := c.call(req, &res); err != nil {
		return SessionRingClearRes{}, err
	}

	return res, nil
}

type SessionRingLastReq struct {
	_msgpack  struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method    string
	Token     string
	SessionID uint32
}

type SessionRingLastRes struct {
	Seq uint32 `msgpack:"seq"`
}

func (c *Client) SessionRingLast(session uint32) (SessionRingLastRes, error) {
	req := &SessionRingLastReq{
		Method:    "session.ring_last",
		Token:     c.token,
		SessionID: session,
	}

	var res SessionRingLastRes
	if err := c.call(req, &res); err != nil {
		return SessionRingLastRes{}, err
	}

	return res, nil
}

func (c *Client) SessionRingPut(session uint32, command string) (SessionRingPutRes, error) {
	req := &SessionRingPutReq{
		Method:    "session.ring_put",
		Token:     c.token,
		SessionID: session,
		Command:   command,
	}

	var res SessionRingPutRes
	if err := c.call(req, &res); err != nil {
		return SessionRingPutRes{}, err
	}

	return res, nil
}

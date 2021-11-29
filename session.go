package gomsf

import (
	"strconv"
)

type sessionListReq struct {
	_msgpack struct{} `msgpack:",asArray"`
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

type sessionWriteReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
	Command   string
}

type sessionWriteRes struct {
	WriteCount string `msgpack:"write_count"`
}

type sessionReadReq struct {
	_msgpack    struct{} `msgpack:",asArray"`
	Method      string
	Token       string
	SessionID   uint32
	ReadPointer string
}

type sessionReadRes struct {
	Seq  uint32 `msgpack:"seq"`
	Data string `msgpack:"data"`
}

type sessionRingLastReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
}

type sessionRingLastRes struct {
	Seq uint32 `msgpack:"seq"`
}

type sessionMeterpreterWriteReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
	Command   string
}

type sessionMeterpreterWriteRes struct {
	Result string `msgpack:"result"`
}

type sessionMeterpreterReadReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
}

type sessionMeterpreterReadRes struct {
	Data string `msgpack:"data"`
}

type sessionMeterpreterRunSingleReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
	Command   string
}

type sessionMeterpreterRunSingleRes sessionMeterpreterWriteRes

type sessionMeterpreterDetachReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
}

type sessionMeterpreterDetachRes sessionMeterpreterWriteRes

type sessionMeterpreterKillReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
}

type sessionMeterpreterKillRes sessionMeterpreterWriteRes

type sessionMeterpreterTabsReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
	InputLine string
}

type sessionMeterpreterTabsRes struct {
	Tabs []string `msgpack:"tabs"`
}

type sessionCompatibleModulesReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
}

type sessionCompatibleModulesRes struct {
	Modules []string `msgpack:"modules"`
}

type sessionShellUpgradeReq struct {
	_msgpack   struct{} `msgpack:",asArray"`
	Method     string
	Token      string
	SessionID  uint32
	IpAddress  string
	PortNumber uint32
}

type sessionShellUpgradeRes sessionMeterpreterWriteRes

type sessionRingClearReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
}

type sessionRingClearRes sessionMeterpreterWriteRes

type sessionRingPutReq struct {
	_msgpack  struct{} `msgpack:",asArray"`
	Method    string
	Token     string
	SessionID uint32
	Command   string
}

type sessionRingPutRes struct {
	WriteCount uint32 `msgpack:"write_count"`
}

func (c *Client) SessionList() (SessionListRes, error) {
	req := &sessionListReq{
		Method: "session.list",
		Token:  c.token,
	}

	var res SessionListRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil

}

func (c *Client) SessionReadPointer(session uint32) (uint32, error) {
	req := &sessionRingLastReq{
		Method:    "session.ring_last",
		Token:     c.token,
		SessionID: session,
	}

	var sesRingLast sessionRingLastRes
	if err := c.call(req, &sesRingLast); err != nil {
		return 0, err
	}

	return sesRingLast.Seq, nil
}

func (c *Client) SessionWrite(session uint32, command string) error {
	req := &sessionWriteReq{
		Method:    "session.shell_write",
		Token:     c.token,
		SessionID: session,
		Command:   command,
	}

	var res sessionWriteRes
	if err := c.call(req, &res); err != nil {
		return err
	}

	return nil
}

func (c *Client) SessionRead(session uint32, readPointer uint32) (string, error) {
	req := &sessionReadReq{
		Method:      "session.shell_read",
		Token:       c.token,
		SessionID:   session,
		ReadPointer: strconv.FormatUint(uint64(readPointer), 10),
	}

	var res sessionReadRes
	if err := c.call(req, &res); err != nil {
		return "", err
	}

	return res.Data, nil
}

func (c *Client) SessionMeterpreterWrite(session uint32, command string) (sessionMeterpreterWriteRes, error) {
	req := &sessionMeterpreterWriteReq{
		Method:    "session.meterpreter_write",
		Token:     c.token,
		SessionID: session,
		Command:   command,
	}

	var res sessionMeterpreterWriteRes
	if err := c.call(req, &res); err != nil {
		return sessionMeterpreterWriteRes{}, err
	}

	return res, nil
}

func (c *Client) SessionMeterpreterRead(session uint32) (sessionMeterpreterReadRes, error) {
	req := &sessionMeterpreterReadReq{
		Method:    "session.meterpreter_read",
		Token:     c.token,
		SessionID: session,
	}

	var res sessionMeterpreterReadRes
	if err := c.call(req, &res); err != nil {
		return sessionMeterpreterReadRes{}, err
	}
	return res, nil
}

func (c *Client) SessionMeterpreterRunSingle(session uint32, command string) (sessionMeterpreterRunSingleRes, error) {
	req := &sessionMeterpreterRunSingleReq{
		Method:    "session.meterpreter_run_single",
		Token:     c.token,
		SessionID: session,
		Command:   command,
	}

	var res sessionMeterpreterRunSingleRes
	if err := c.call(req, &res); err != nil {
		return sessionMeterpreterRunSingleRes{}, err
	}

	return res, nil
}

func (c *Client) SessionMeterpreterSessionDetach(session uint32) (sessionMeterpreterDetachRes, error) {
	req := &sessionMeterpreterDetachReq{
		Method:    "session.meterpreter_session_detach",
		Token:     c.token,
		SessionID: session,
	}

	var res sessionMeterpreterDetachRes
	if err := c.call(req, &res); err != nil {
		return sessionMeterpreterDetachRes{}, err
	}
	return res, nil
}

func (c *Client) SessionMeterpreterSessionKill(session uint32) (sessionMeterpreterKillRes, error) {
	req := &sessionMeterpreterKillReq{
		Method:    "session.meterpreter_session_kill",
		Token:     c.token,
		SessionID: session,
	}

	var res sessionMeterpreterKillRes
	if err := c.call(req, &res); err != nil {
		return sessionMeterpreterKillRes{}, err
	}
	return res, nil
}

func (c *Client) SessionMeterpreterTabs(session uint32, inputLine string) (sessionMeterpreterTabsRes, error) {
	req := &sessionMeterpreterTabsReq{
		Method:    "session.meterpreter_tabs",
		Token:     c.token,
		SessionID: session,
		InputLine: inputLine,
	}

	var res sessionMeterpreterTabsRes
	if err := c.call(req, &res); err != nil {
		return sessionMeterpreterTabsRes{}, err
	}
	return res, nil
}

func (c *Client) SessionCompatibleModules(session uint32) (sessionCompatibleModulesRes, error) {
	req := &sessionCompatibleModulesReq{
		Method:    "session.compatible_modules",
		Token:     c.token,
		SessionID: session,
	}

	var res sessionCompatibleModulesRes
	if err := c.call(req, &res); err != nil {
		return sessionCompatibleModulesRes{}, err
	}
	return res, nil
}

func (c *Client) SessionShellUpgrade(session uint32, lhostAddress string, lportNumber uint32) (sessionShellUpgradeRes, error) {
	req := &sessionShellUpgradeReq{
		Method:     "session.shell_upgrade",
		Token:      c.token,
		SessionID:  session,
		IpAddress:  lhostAddress,
		PortNumber: lportNumber,
	}

	var res sessionShellUpgradeRes
	if err := c.call(req, &res); err != nil {
		return sessionShellUpgradeRes{}, err
	}
	return res, nil
}

func (c *Client) SessionRingClear(session uint32) (sessionRingClearRes, error) {
	req := &sessionRingClearReq{
		Method:    "session.ring_clear",
		Token:     c.token,
		SessionID: session,
	}

	var res sessionRingClearRes
	if err := c.call(req, &res); err != nil {
		return sessionRingClearRes{}, err
	}
	return res, nil
}

func (c *Client) SessionRingLast(session uint32) (sessionRingLastRes, error) {
	req := &sessionRingLastReq{
		Method:    "session.ring_last",
		Token:     c.token,
		SessionID: session,
	}

	var res sessionRingLastRes
	if err := c.call(req, &res); err != nil {
		return sessionRingLastRes{}, err
	}
	return res, nil
}

func (c *Client) SessionRingPut(session uint32, command string) (sessionRingPutRes, error) {
	req := &sessionRingPutReq{
		Method:    "session.ring_put",
		Token:     c.token,
		SessionID: session,
		Command:   command,
	}

	var res sessionRingPutRes
	if err := c.call(req, &res); err != nil {
		return sessionRingPutRes{}, err
	}
	return res, nil
}

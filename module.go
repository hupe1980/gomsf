package gomsf

type ModuleType string

const (
	Exploit   ModuleType = "exploit"
	Auxiliary ModuleType = "auxiliary"
	Post      ModuleType = "post"
	Payload   ModuleType = "payload"
	Evasion   ModuleType = "evasion"
)

type ModuleArchitecturesReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
}

type ModuleArchitecturesRes []string

// ModuleArchitectures returns a list of architecture names
func (c *Client) ModuleArchitectures() (*ModuleArchitecturesRes, error) {
	req := &ModuleArchitecturesReq{
		Method: "module.architectures",
		Token:  c.token,
	}

	var res *ModuleArchitecturesRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModuleExploitsReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
}

type ModuleExploitsRes struct {
	Modules []string `msgpack:"modules"`
}

func (c *Client) ModuleExploits() (*ModuleExploitsRes, error) {
	req := &ModuleExploitsReq{
		Method: "module.exploits",
		Token:  c.token,
	}

	var res *ModuleExploitsRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModuleAuxiliaryReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
}

type ModuleAuxiliaryRes struct {
	Modules []string `msgpack:"modules"`
}

// ModuleAuxiliary returns a list of auxiliary module names
func (c *Client) ModuleAuxiliary() (*ModuleAuxiliaryRes, error) {
	req := &ModuleAuxiliaryReq{
		Method: "module.auxiliary",
		Token:  c.token,
	}

	var res *ModuleAuxiliaryRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

// CHECK

// CompatibleEvasionPayloads
type ModuleCompatiblePayloadsReq struct {
	_msgpack   struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method     string
	Token      string
	ModuleName string
}

type ModuleCompatiblePayloadsRes struct {
	Payloads []string `msgpack:"payloads"`
}

// ModuleCompatiblePayloads returns the compatible payloads for a specific exploit
func (c *Client) ModuleCompatiblePayloads(moduleName string) (*ModuleCompatiblePayloadsRes, error) {
	req := &ModuleCompatiblePayloadsReq{
		Method:     "module.compatible_payloads",
		Token:      c.token,
		ModuleName: moduleName,
	}

	var res *ModuleCompatiblePayloadsRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModuleCompatibleSessionsReq struct {
	_msgpack   struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method     string
	Token      string
	ModuleName string
}

type ModuleCompatibleSessionsRes struct {
	Sessions []string `msgpack:"sessions"`
}

// ModuleCompatibleSessions returns the compatible sessions for a specific post module
func (c *Client) ModuleCompatibleSessions(moduleName string) (*ModuleCompatibleSessionsRes, error) {
	req := &ModuleCompatibleSessionsReq{
		Method:     "module.compatible_sessions",
		Token:      c.token,
		ModuleName: moduleName,
	}

	var res *ModuleCompatibleSessionsRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type EncodingOptions struct {
	Format       string `msgpack:"format,omitempty"`        // Encoding format
	Badchars     string `msgpack:"badchars,omitempty"`      // Bad characters
	Platform     string `msgpack:"platform,omitempty"`      // Platform
	Arch         string `msgpack:"arch,omitempty"`          // Architecture
	ECount       int    `msgpack:"ecount,omitempty"`        // Number of times to encode
	Inject       bool   `msgpack:"inject,omitempty"`        // Enable injection
	Template     string `msgpack:"template,omitempty"`      // The template file (an executable)
	TemplatePath string `msgpack:"template_path,omitempty"` // Template path
	Addshellcode string `msgpack:"addshellcode,omitempty"`  // Custom shellcode
}

type ModuleEncodeReq struct {
	_msgpack      struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method        string
	Token         string
	Data          string
	EncoderModule string
	Options       *EncodingOptions
}

type ModuleEncodeRes struct {
	Encoded []byte `msgpack:"encoded"`
}

// ModuleEnoce encodes data with an encoder
func (c *Client) ModuleEncode(data, encoderModule string, moduleOptions *EncodingOptions) (*ModuleEncodeRes, error) {
	req := &ModuleEncodeReq{
		Method:        "module.encode",
		Token:         c.token,
		Data:          data,
		EncoderModule: encoderModule,
		Options:       moduleOptions,
	}

	var res *ModuleEncodeRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModulePostReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
}

type ModulePostRes struct {
	Modules []string `msgpack:"modules"`
}

func (c *Client) ModulePost() (*ModulePostRes, error) {
	req := &ModulePostReq{
		Method: "module.post",
		Token:  c.token,
	}

	var res *ModulePostRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModulePayloadsReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
}

type ModulePayloadsRes struct {
	Modules []string `msgpack:"modules"`
}

func (c *Client) ModulePayloads() (*ModulePayloadsRes, error) {
	req := &ModulePayloadsReq{
		Method: "module.payloads",
		Token:  c.token,
	}

	var res *ModulePayloadsRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModuleEncodersReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
}

type ModuleEncodersRes struct {
	Modules []string `msgpack:"modules"`
}

func (c *Client) ModuleEncoders() (*ModuleEncodersRes, error) {
	req := &ModuleEncodersReq{
		Method: "module.encoders",
		Token:  c.token,
	}

	var res *ModuleEncodersRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModuleNopsReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
}

type ModuleNopsRes struct {
	Modules []string `msgpack:"modules"`
}

func (c *Client) ModuleNops() (*ModuleNopsRes, error) {
	req := &ModuleNopsReq{
		Method: "module.nops",
		Token:  c.token,
	}

	var res *ModuleNopsRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModuleInfoReq struct {
	_msgpack   struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method     string
	Token      string
	ModuleType ModuleType
	ModuleName string
}

type ModuleInfoRes struct {
	Name        string     `msgpack:"name"`
	Description string     `msgpack:"description"`
	License     string     `msgpack:"license"`
	FilePath    string     `msgpack:"filepath"`
	Version     string     `msgpack:"version"`
	Rank        string     `msgpack:"rank"`
	References  [][]string `msgpack:"references"`
	Authors     []string   `msgpack:"authors"`
}

// ModuleInfo returns the metadata for a module
func (c *Client) ModuleInfo(moduleType ModuleType, moduleName string) (*ModuleInfoRes, error) {
	req := &ModuleInfoReq{
		Method:     "module.info",
		Token:      c.token,
		ModuleType: moduleType,
		ModuleName: moduleName,
	}

	var res *ModuleInfoRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModuleOptionsReq struct {
	_msgpack   struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method     string
	Token      string
	ModuleType ModuleType
	ModuleName string
}

type ModuleOptionsRes map[string]struct {
	Type     string      `msgpack:"type"`
	Required bool        `msgpack:"required"`
	Advanced bool        `msgpack:"advanced"`
	Evasion  bool        `msgpack:"evasion"`
	Desc     string      `msgpack:"desc"`
	Default  interface{} `msgpack:"default"`
	Enums    []string    `msgpack:"enums,omitempty"`
}

func (c *Client) ModuleOptions(moduleType ModuleType, moduleName string) (*ModuleOptionsRes, error) {
	req := &ModuleOptionsReq{
		Method:     "module.options",
		Token:      c.token,
		ModuleType: moduleType,
		ModuleName: moduleName,
	}

	var res *ModuleOptionsRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModuleTargetCompatiblePayloadsReq struct {
	_msgpack   struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method     string
	Token      string
	ModuleName string
	ArchNumber uint32
}

type ModuleTargetCompatiblePayloadsRes struct {
	Payloads []string `msgpack:"payloads"`
}

func (c *Client) ModuleTargetCompatiblePayloads(moduleName string, targetNumber uint32) (*ModuleTargetCompatiblePayloadsRes, error) {
	req := &ModuleTargetCompatiblePayloadsReq{
		Method:     "module.target_compatible_payloads",
		Token:      c.token,
		ModuleName: moduleName,
		ArchNumber: targetNumber,
	}

	var res *ModuleTargetCompatiblePayloadsRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModuleExecuteReq struct {
	_msgpack   struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method     string
	Token      string
	ModuleType ModuleType
	ModuleName string
	Options    map[string]string
}

type ModuleExecuteRes struct {
	JobID uint32 `msgpack:"job_id"`
}

func (c *Client) ModuleExecute(moduleType ModuleType, moduleName string, moduleOptions map[string]string) (*ModuleExecuteRes, error) {
	req := &ModuleExecuteReq{
		Method:     "module.execute",
		Token:      c.token,
		ModuleType: moduleType,
		ModuleName: moduleName,
		Options:    moduleOptions,
	}

	var res *ModuleExecuteRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

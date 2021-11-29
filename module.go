package gomsf

type ModuleType string

const (
	Exploit   ModuleType = "exploit"
	Auxiliary ModuleType = "auxiliary"
	Post      ModuleType = "post"
	Payload   ModuleType = "payload"
	Evasion   ModuleType = "evasion"
)

type moduleArchitecturesReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
}

type moduleArchitecturesRes []string

// ModuleArchitectures returns a list of architecture names
func (c *Client) ModuleArchitectures() (*moduleArchitecturesRes, error) {
	req := &moduleArchitecturesReq{
		Method: "module.architectures",
		Token:  c.token,
	}
	var res *moduleArchitecturesRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type moduleExploitsReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
}

type moduleExploitsRes struct {
	Modules []string `msgpack:"modules"`
}

func (c *Client) ModuleExploits() (*moduleExploitsRes, error) {
	req := &moduleExploitsReq{
		Method: "module.exploits",
		Token:  c.token,
	}
	var res *moduleExploitsRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type moduleAuxiliaryReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
}

type moduleAuxiliaryRes struct {
	Modules []string `msgpack:"modules"`
}

// ModuleAuxiliary returns a list of auxiliary module names
func (c *Client) ModuleAuxiliary() (*moduleAuxiliaryRes, error) {
	req := &moduleAuxiliaryReq{
		Method: "module.auxiliary",
		Token:  c.token,
	}
	var res *moduleAuxiliaryRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// CHECK

// CompatibleEvasionPayloads
type moduleCompatiblePayloadsReq struct {
	_msgpack   struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method     string
	Token      string
	ModuleName string
}

type moduleCompatiblePayloadsRes struct {
	Payloads []string `msgpack:"payloads"`
}

// ModuleCompatiblePayloads returns the compatible payloads for a specific exploit
func (c *Client) ModuleCompatiblePayloads(moduleName string) (*moduleCompatiblePayloadsRes, error) {
	req := &moduleCompatiblePayloadsReq{
		Method:     "module.compatible_payloads",
		Token:      c.token,
		ModuleName: moduleName,
	}
	var res *moduleCompatiblePayloadsRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type moduleCompatibleSessionsReq struct {
	_msgpack   struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method     string
	Token      string
	ModuleName string
}

type moduleCompatibleSessionsRes struct {
	Sessions []string `msgpack:"sessions"`
}

// ModuleCompatibleSessions returns the compatible sessions for a specific post module
func (c *Client) ModuleCompatibleSessions(moduleName string) (*moduleCompatibleSessionsRes, error) {
	req := &moduleCompatibleSessionsReq{
		Method:     "module.compatible_sessions",
		Token:      c.token,
		ModuleName: moduleName,
	}
	var res *moduleCompatibleSessionsRes
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

type moduleEncodeReq struct {
	_msgpack      struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method        string
	Token         string
	Data          string
	EncoderModule string
	Options       EncodingOptions
}

type moduleEncodeRes struct {
	Encoded []byte `msgpack:"encoded"`
}

// ModuleEnoce encodes data with an encoder
func (c *Client) ModuleEncode(data, encoderModule string, moduleOptions EncodingOptions) (*moduleEncodeRes, error) {
	req := &moduleEncodeReq{
		Method:        "module.encode",
		Token:         c.token,
		Data:          data,
		EncoderModule: encoderModule,
		Options:       moduleOptions,
	}
	var res *moduleEncodeRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type modulePostReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
}

type modulePostRes struct {
	Modules []string `msgpack:"modules"`
}

func (c *Client) ModulePost() (*modulePostRes, error) {
	req := &modulePostReq{
		Method: "module.post",
		Token:  c.token,
	}
	var res *modulePostRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type modulePayloadsReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
}

type modulePayloadsRes struct {
	Modules []string `msgpack:"modules"`
}

func (c *Client) ModulePayloads() (*modulePayloadsRes, error) {
	req := &modulePayloadsReq{
		Method: "module.payloads",
		Token:  c.token,
	}
	var res *modulePayloadsRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type moduleEncodersReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
}

type moduleEncodersRes struct {
	Modules []string `msgpack:"modules"`
}

func (c *Client) ModuleEncoders() (*moduleEncodersRes, error) {
	req := &moduleEncodersReq{
		Method: "module.encoders",
		Token:  c.token,
	}
	var res *moduleEncodersRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type moduleNopsReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
}

type moduleNopsRes struct {
	Modules []string `msgpack:"modules"`
}

func (c *Client) ModuleNops() (*moduleNopsRes, error) {
	req := &moduleNopsReq{
		Method: "module.nops",
		Token:  c.token,
	}
	var res *moduleNopsRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type moduleInfoReq struct {
	_msgpack   struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method     string
	Token      string
	ModuleType ModuleType
	ModuleName string
}

type moduleInfoRes struct {
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
func (c *Client) ModuleInfo(moduleType ModuleType, moduleName string) (*moduleInfoRes, error) {
	req := &moduleInfoReq{
		Method:     "module.info",
		Token:      c.token,
		ModuleType: moduleType,
		ModuleName: moduleName,
	}
	var res *moduleInfoRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type moduleOptionsReq struct {
	_msgpack   struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method     string
	Token      string
	ModuleType ModuleType
	ModuleName string
}

type moduleOptionsRes map[string]struct {
	Type     string      `msgpack:"type"`
	Required bool        `msgpack:"required"`
	Advanced bool        `msgpack:"advanced"`
	Evasion  bool        `msgpack:"evasion"`
	Desc     string      `msgpack:"desc"`
	Default  interface{} `msgpack:"default"`
	Enums    []string    `msgpack:"enums,omitempty"`
}

func (c *Client) ModuleOptions(moduleType ModuleType, moduleName string) (*moduleOptionsRes, error) {
	req := &moduleOptionsReq{
		Method:     "module.options",
		Token:      c.token,
		ModuleType: moduleType,
		ModuleName: moduleName,
	}
	var res *moduleOptionsRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type moduleTargetCompatiblePayloadsReq struct {
	_msgpack   struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method     string
	Token      string
	ModuleName string
	ArchNumber uint32
}

type moduleTargetCompatiblePayloadsRes struct {
	Payloads []string `msgpack:"payloads"`
}

func (c *Client) ModuleTargetCompatiblePayloads(moduleName string, targetNumber uint32) (*moduleTargetCompatiblePayloadsRes, error) {
	req := &moduleTargetCompatiblePayloadsReq{
		Method:     "module.target_compatible_payloads",
		Token:      c.token,
		ModuleName: moduleName,
		ArchNumber: targetNumber,
	}
	var res *moduleTargetCompatiblePayloadsRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type moduleExecuteReq struct {
	_msgpack   struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method     string
	Token      string
	ModuleType ModuleType
	ModuleName string
	Options    map[string]string
}

type moduleExecuteRes struct {
	JobID uint32 `msgpack:"job_id"`
}

func (c *Client) ModuleExecute(moduleType ModuleType, moduleName string, moduleOptions map[string]string) (*moduleExecuteRes, error) {
	req := &moduleExecuteReq{
		Method:     "module.execute",
		Token:      c.token,
		ModuleType: moduleType,
		ModuleName: moduleName,
		Options:    moduleOptions,
	}
	var res *moduleExecuteRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

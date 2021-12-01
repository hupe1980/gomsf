package rpc

type module struct {
	rpc *RPC
}

type ModuleType string

const (
	Exploit   ModuleType = "exploit"
	Auxiliary ModuleType = "auxiliary"
	Post      ModuleType = "post"
	Payload   ModuleType = "payload"
	Evasion   ModuleType = "evasion"
)

type ModuleArchitecturesReq struct {
	Method string
	Token  string
}

type ModuleArchitecturesRes []string

// Architectures returns a list of architecture names
func (m *module) Architectures() (*ModuleArchitecturesRes, error) {
	req := &ModuleArchitecturesReq{
		Method: "module.architectures",
		Token:  m.rpc.Token(),
	}

	var res *ModuleArchitecturesRes
	if err := m.rpc.Call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModuleExploitsReq struct {
	Method string
	Token  string
}

type ModuleExploitsRes struct {
	Modules []string `msgpack:"modules"`
}

func (m *module) Exploits() (*ModuleExploitsRes, error) {
	req := &ModuleExploitsReq{
		Method: "module.exploits",
		Token:  m.rpc.Token(),
	}

	var res *ModuleExploitsRes
	if err := m.rpc.Call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModuleAuxiliaryReq struct {
	Method string
	Token  string
}

type ModuleAuxiliaryRes struct {
	Modules []string `msgpack:"modules"`
}

// ModuleAuxiliary returns a list of auxiliary module names
func (m *module) Auxiliary() (*ModuleAuxiliaryRes, error) {
	req := &ModuleAuxiliaryReq{
		Method: "module.auxiliary",
		Token:  m.rpc.Token(),
	}

	var res *ModuleAuxiliaryRes
	if err := m.rpc.Call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

// CHECK

// CompatibleEvasionPayloads
type ModuleCompatiblePayloadsReq struct {
	Method     string
	Token      string
	ModuleName string
}

type ModuleCompatiblePayloadsRes struct {
	Payloads []string `msgpack:"payloads"`
}

// ModuleCompatiblePayloads returns the compatible payloads for a specific exploit
func (m *module) CompatiblePayloads(moduleName string) (*ModuleCompatiblePayloadsRes, error) {
	req := &ModuleCompatiblePayloadsReq{
		Method:     "module.compatible_payloads",
		Token:      m.rpc.Token(),
		ModuleName: moduleName,
	}

	var res *ModuleCompatiblePayloadsRes
	if err := m.rpc.Call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModuleCompatibleSessionsReq struct {
	Method     string
	Token      string
	ModuleName string
}

type ModuleCompatibleSessionsRes struct {
	Sessions []string `msgpack:"sessions"`
}

// ModuleCompatibleSessions returns the compatible sessions for a specific post module
func (m *module) CompatibleSessions(moduleName string) (*ModuleCompatibleSessionsRes, error) {
	req := &ModuleCompatibleSessionsReq{
		Method:     "module.compatible_sessions",
		Token:      m.rpc.Token(),
		ModuleName: moduleName,
	}

	var res *ModuleCompatibleSessionsRes
	if err := m.rpc.Call(req, &res); err != nil {
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
	Method        string
	Token         string
	Data          string
	EncoderModule string
	Options       *EncodingOptions
}

type ModuleEncodeRes struct {
	Encoded []byte `msgpack:"encoded"`
}

// Encode encodes data with an encoder
func (m *module) Encode(data, encoderModule string, moduleOptions *EncodingOptions) (*ModuleEncodeRes, error) {
	req := &ModuleEncodeReq{
		Method:        "module.encode",
		Token:         m.rpc.Token(),
		Data:          data,
		EncoderModule: encoderModule,
		Options:       moduleOptions,
	}

	var res *ModuleEncodeRes
	if err := m.rpc.Call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModulePostReq struct {
	Method string
	Token  string
}

type ModulePostRes struct {
	Modules []string `msgpack:"modules"`
}

func (m *module) Post() (*ModulePostRes, error) {
	req := &ModulePostReq{
		Method: "module.post",
		Token:  m.rpc.Token(),
	}

	var res *ModulePostRes
	if err := m.rpc.Call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModulePayloadsReq struct {
	Method string
	Token  string
}

type ModulePayloadsRes struct {
	Modules []string `msgpack:"modules"`
}

func (m *module) Payloads() (*ModulePayloadsRes, error) {
	req := &ModulePayloadsReq{
		Method: "module.payloads",
		Token:  m.rpc.Token(),
	}

	var res *ModulePayloadsRes
	if err := m.rpc.Call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModuleEncodersReq struct {
	Method string
	Token  string
}

type ModuleEncodersRes struct {
	Modules []string `msgpack:"modules"`
}

func (m *module) Encoders() (*ModuleEncodersRes, error) {
	req := &ModuleEncodersReq{
		Method: "module.encoders",
		Token:  m.rpc.Token(),
	}

	var res *ModuleEncodersRes
	if err := m.rpc.Call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModuleNopsReq struct {
	Method string
	Token  string
}

type ModuleNopsRes struct {
	Modules []string `msgpack:"modules"`
}

func (m *module) Nops() (*ModuleNopsRes, error) {
	req := &ModuleNopsReq{
		Method: "module.nops",
		Token:  m.rpc.Token(),
	}

	var res *ModuleNopsRes
	if err := m.rpc.Call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModuleInfoReq struct {
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

// Info returns the metadata for a module
func (m *module) Info(moduleType ModuleType, moduleName string) (*ModuleInfoRes, error) {
	req := &ModuleInfoReq{
		Method:     "module.info",
		Token:      m.rpc.Token(),
		ModuleType: moduleType,
		ModuleName: moduleName,
	}

	var res *ModuleInfoRes
	if err := m.rpc.Call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModuleOptionsReq struct {
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

func (m *module) Options(moduleType ModuleType, moduleName string) (*ModuleOptionsRes, error) {
	req := &ModuleOptionsReq{
		Method:     "module.options",
		Token:      m.rpc.Token(),
		ModuleType: moduleType,
		ModuleName: moduleName,
	}

	var res *ModuleOptionsRes
	if err := m.rpc.Call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModuleTargetCompatiblePayloadsReq struct {
	Method     string
	Token      string
	ModuleName string
	ArchNumber uint32
}

type ModuleTargetCompatiblePayloadsRes struct {
	Payloads []string `msgpack:"payloads"`
}

func (m *module) TargetCompatiblePayloads(moduleName string, targetNumber uint32) (*ModuleTargetCompatiblePayloadsRes, error) {
	req := &ModuleTargetCompatiblePayloadsReq{
		Method:     "module.target_compatible_payloads",
		Token:      m.rpc.Token(),
		ModuleName: moduleName,
		ArchNumber: targetNumber,
	}

	var res *ModuleTargetCompatiblePayloadsRes
	if err := m.rpc.Call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type ModuleOptions struct {
	Options map[string]interface{}
}

func NewModuleOptions() *ModuleOptions {
	return &ModuleOptions{
		Options: make(map[string]interface{}),
	}
}

func (e *ModuleOptions) SetStringOption(name, value string) {
	e.Options[name] = value
}

func (e *ModuleOptions) SetIntOption(name string, value int) {
	e.Options[name] = value
}

func (e *ModuleOptions) SetBoolOption(name string, value bool) {
	e.Options[name] = value
}

type ModuleExecuteReq struct {
	Method     string
	Token      string
	ModuleType ModuleType
	ModuleName string
	Options    map[string]interface{}
}

type ModuleExecuteRes struct {
	JobID uint32 `msgpack:"job_id"`
	UUID  string `msgpack:"uuid"`
}

func (m *module) Execute(moduleType ModuleType, moduleName string, options *ModuleOptions) (*ModuleExecuteRes, error) {
	req := &ModuleExecuteReq{
		Method:     "module.execute",
		Token:      m.rpc.Token(),
		ModuleType: moduleType,
		ModuleName: moduleName,
		Options:    options.Options,
	}

	var res *ModuleExecuteRes
	if err := m.rpc.Call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

package gomsf

import (
	"fmt"

	"github.com/fatih/structs"
	"github.com/hupe1980/gomsf/rpc"
)

type ModuleType string

const (
	ExploitType   ModuleType = "exploit"
	AuxiliaryType ModuleType = "auxiliary"
	PostType      ModuleType = "post"
	PayloadType   ModuleType = "payload"
	EvasionType   ModuleType = "evasion"
)

type module struct {
	rpc        *rpc.RPC
	moduleType ModuleType
	moduleName string
	info       *rpc.ModuleInfoRes
	options    *rpc.ModuleOptionsRes
}

func newModule(rpc *rpc.RPC, moduleType ModuleType, moduleName string) (*module, error) {
	info, err := rpc.Module.Info(string(moduleType), moduleName)
	if err != nil {
		return nil, err
	}

	options, err := rpc.Module.Options(string(moduleType), moduleName)
	if err != nil {
		return nil, err
	}

	return &module{
		rpc:        rpc,
		moduleType: moduleType,
		moduleName: moduleName,
		info:       info,
		options:    options,
	}, nil
}

func (m *module) Options() []string {
	keys := make([]string, 0, len(*m.options))
	for k := range *m.options {
		keys = append(keys, k)
	}

	return keys
}

func (m *module) Required() []string {
	var keys []string

	for k, v := range *m.options {
		if v.Required {
			keys = append(keys, k)
		}
	}

	return keys
}

type Exploit struct {
	*module
}

func (e *Exploit) Payloads() ([]string, error) {
	r, err := e.rpc.Module.CompatiblePayloads(e.moduleName)
	if err != nil {
		return nil, err
	}

	return r.Payloads, nil
}

type Post struct {
	*module
}

type Auxiliary struct {
	*module
}

type Payload struct {
	*module
}

type ModuleManager struct {
	rpc *rpc.RPC
}

func (mm *ModuleManager) Architectures() (*rpc.ModuleArchitecturesRes, error) {
	return mm.rpc.Module.Architectures()
}

func (mm *ModuleManager) CompatibleSessions(moduleName string) ([]string, error) {
	r, err := mm.rpc.Module.CompatibleSessions(moduleName)
	if err != nil {
		return nil, err
	}

	return r.Sessions, nil
}

func (mm *ModuleManager) Info(moduleType ModuleType, moduleName string) (*rpc.ModuleInfoRes, error) {
	return mm.rpc.Module.Info(string(moduleType), moduleName)
}

func (mm *ModuleManager) Execute(moduleType ModuleType, moduleName string, options map[string]string) (*rpc.ModuleExecuteRes, error) {
	return mm.rpc.Module.Execute(string(moduleType), moduleName, options)
}

type EncodeOptions struct {
	Format       string `structs:"format,omitempty"`        // Encoding format
	Badchars     string `structs:"badchars,omitempty"`      // Bad characters
	Platform     string `structs:"platform,omitempty"`      // Platform
	Arch         string `structs:"arch,omitempty"`          // Architecture
	ECount       int    `structs:"ecount,omitempty"`        // Number of times to encode
	Inject       bool   `structs:"inject,omitempty"`        // Enable injection
	Template     string `structs:"template,omitempty"`      // The template file (an executable)
	TemplatePath string `structs:"template_path,omitempty"` // Template path
	Addshellcode string `structs:"addshellcode,omitempty"`  // Custom shellcode
}

func (mm *ModuleManager) Encode(data string, encoderModule string, options *EncodeOptions) ([]byte, error) {
	sMap := structs.Map(options)

	optMap := make(map[string]string)
	for k, v := range sMap {
		optMap[k] = fmt.Sprintf("%v", v)
	}

	r, err := mm.rpc.Module.Encode(data, encoderModule, optMap)
	if err != nil {
		return nil, err
	}

	return r.Encoded, nil
}

func (mm *ModuleManager) Exploits() ([]string, error) {
	r, err := mm.rpc.Module.Exploits()
	if err != nil {
		return nil, err
	}

	return r.Modules, nil
}

func (mm *ModuleManager) Evasions() ([]string, error) {
	r, err := mm.rpc.Module.Evasion()
	if err != nil {
		return nil, err
	}

	return r.Modules, nil
}

func (mm *ModuleManager) Payloads() ([]string, error) {
	r, err := mm.rpc.Module.Payloads()
	if err != nil {
		return nil, err
	}

	return r.Modules, nil
}

func (mm *ModuleManager) Auxiliaries() ([]string, error) {
	r, err := mm.rpc.Module.Auxiliary()
	if err != nil {
		return nil, err
	}

	return r.Modules, nil
}

func (mm *ModuleManager) Posts() ([]string, error) {
	r, err := mm.rpc.Module.Post()
	if err != nil {
		return nil, err
	}

	return r.Modules, nil
}

func (mm *ModuleManager) Nops() ([]string, error) {
	r, err := mm.rpc.Module.Nops()
	if err != nil {
		return nil, err
	}

	return r.Modules, nil
}

func (mm *ModuleManager) Encoders() ([]string, error) {
	r, err := mm.rpc.Module.Encoders()
	if err != nil {
		return nil, err
	}

	return r.Modules, nil
}

func (mm *ModuleManager) Platforms() (*rpc.ModulePlatformsRes, error) {
	return mm.rpc.Module.Platforms()
}

func (mm *ModuleManager) UseExploit(moduleName string) (*Exploit, error) {
	m, err := newModule(mm.rpc, ExploitType, moduleName)
	if err != nil {
		return nil, err
	}

	return &Exploit{
		module: m,
	}, nil
}

func (mm *ModuleManager) UseAuxiliary(moduleName string) (*Auxiliary, error) {
	m, err := newModule(mm.rpc, AuxiliaryType, moduleName)
	if err != nil {
		return nil, err
	}

	return &Auxiliary{
		module: m,
	}, nil
}

func (mm *ModuleManager) UsePost(moduleName string) (*Post, error) {
	m, err := newModule(mm.rpc, PostType, moduleName)
	if err != nil {
		return nil, err
	}

	return &Post{
		module: m,
	}, nil
}

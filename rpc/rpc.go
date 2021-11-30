package rpc

type Result string

const (
	SUCCESS Result = "success"
	FAILURE Result = "failure"
)

type Client interface {
	Call(req, res interface{}) error
	Token() string
}

type RPC struct {
	client  Client
	Auth    *auth
	Console *console
	Core    *core
	Health  *health
	Job     *job
	Module  *module
	Plugin  *plugin
	Session *session
}

func NewRPC(client Client) *RPC {
	rpc := &RPC{
		client: client,
	}

	rpc.Auth = &auth{client: client}
	rpc.Console = &console{client: client}
	rpc.Core = &core{client: client}
	rpc.Health = &health{client: client}
	rpc.Job = &job{client: client}
	rpc.Module = &module{client: client}
	rpc.Plugin = &plugin{client: client}
	rpc.Session = &session{client: client}

	return rpc
}

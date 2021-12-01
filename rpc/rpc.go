package rpc

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"reflect"

	"github.com/vmihailenco/msgpack/v5"
)

type Result string

const (
	SUCCESS Result = "success"
	FAILURE Result = "failure"
)

type RPC struct {
	http    *http.Client
	url     string
	token   string
	Auth    *auth
	Console *console
	Core    *core
	Health  *health
	Job     *job
	Module  *module
	Plugin  *plugin
	Session *session
}

func NewRPC(http *http.Client, url string) *RPC {
	rpc := &RPC{
		http: http,
		url:  url,
	}

	rpc.Auth = &auth{rpc: rpc}
	rpc.Console = &console{rpc: rpc}
	rpc.Core = &core{rpc: rpc}
	rpc.Health = &health{rpc: rpc}
	rpc.Job = &job{rpc: rpc}
	rpc.Module = &module{rpc: rpc}
	rpc.Plugin = &plugin{rpc: rpc}
	rpc.Session = &session{rpc: rpc}

	return rpc
}

func (r *RPC) Call(req, res interface{}) error {
	method := rpcMethod(req)
	if method != "auth.login" && method != "health.check" {
		if r.token == "" {
			return errors.New("client not authenticated")
		}
	}

	buf := new(bytes.Buffer)
	enc := msgpack.NewEncoder(buf)
	enc.UseArrayEncodedStructs(true)

	if err := enc.Encode(req); err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(context.Background(), "POST", r.url, buf)
	if err != nil {
		return err
	}

	request.Header.Add("Content-Type", "binary/message-pack")

	response, err := r.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if res != nil {
		if err := msgpack.NewDecoder(response.Body).Decode(res); err != nil {
			return err
		}
	}

	return nil
}

func (r *RPC) Token() string {
	return r.token
}

func (r *RPC) SetToken(token string) {
	r.token = token
}

func rpcMethod(req interface{}) string {
	stype := reflect.ValueOf(req).Elem()
	field := stype.FieldByName("Method")

	if field.IsValid() {
		return field.String()
	}

	return ""
}

package gomsf

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hupe1980/gomsf/rpc"
	"github.com/stretchr/testify/assert"
	"github.com/vmihailenco/msgpack/v5"
)

func TestLogin(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = msgpack.NewEncoder(w).Encode(&rpc.AuthLoginRes{
			Result: "success",
			Token:  "token",
		})
	}))
	defer ts.Close()

	client := &Client{
		token:  "", // no token
		url:    ts.URL,
		client: http.DefaultClient,
	}
	client.rpc = rpc.NewRPC(client)
	client.Auth = &AuthManager{rpc: client.rpc}

	err := client.Login("user", "pass")
	assert.NoError(t, err)
	assert.Equal(t, true, client.Authenticated())
}

func TestLogout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = msgpack.NewEncoder(w).Encode(&rpc.AuthLogoutRes{
			Result: "success",
		})
	}))
	defer ts.Close()

	client := &Client{
		token:  "token",
		url:    ts.URL,
		client: http.DefaultClient,
	}
	client.rpc = rpc.NewRPC(client)
	client.Auth = &AuthManager{rpc: client.rpc}

	err := client.Logout()
	assert.NoError(t, err)
	assert.Equal(t, false, client.Authenticated())
	assert.Equal(t, "", client.Token())
}

func TestNoAuthError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	client := &Client{
		token:  "", // no token
		url:    ts.URL,
		client: http.DefaultClient,
	}
	client.rpc = rpc.NewRPC(client)
	client.Core = &CoreManager{rpc: client.rpc}

	_, err := client.Core.Version()
	assert.Error(t, err)
	assert.Equal(t, "client not authenticated", err.Error())
}

func TestRPCMethod(t *testing.T) {
	type dummy struct {
		Method string
	}

	method := rpcMethod(&dummy{Method: "foo"})

	assert.Equal(t, "foo", method)
}

func TestRPCCall(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = msgpack.NewEncoder(w).Encode(&rpc.CoreVersionRes{
			Version: "4711",
			Ruby:    "ruby",
			API:     "api",
		})
	}))
	defer ts.Close()

	client := &Client{
		token:  "token",
		url:    ts.URL,
		client: http.DefaultClient,
	}
	client.rpc = rpc.NewRPC(client)
	client.Core = &CoreManager{rpc: client.rpc}

	result, err := client.Core.Version()
	assert.NoError(t, err)
	assert.Equal(t, "4711", result.Version)
	assert.Equal(t, "ruby", result.Ruby)
	assert.Equal(t, "api", result.API)
}

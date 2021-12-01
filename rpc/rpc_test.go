package rpc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vmihailenco/msgpack/v5"
)

func TestRPCCall(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = msgpack.NewEncoder(w).Encode(&CoreVersionRes{
			Version: "4711",
			Ruby:    "ruby",
			API:     "api",
		})
	}))
	defer ts.Close()

	rpc := NewRPC(http.DefaultClient, ts.URL)
	rpc.SetToken("token")

	result, err := rpc.Core.Version()

	assert.NoError(t, err)
	assert.Equal(t, "4711", result.Version)
	assert.Equal(t, "ruby", result.Ruby)
	assert.Equal(t, "api", result.API)
}

func TestRPCMethod(t *testing.T) {
	type dummy struct {
		Method string
	}

	method := rpcMethod(&dummy{Method: "foo"})

	assert.Equal(t, "foo", method)
}

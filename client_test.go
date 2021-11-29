package gomsf

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNoAuth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	client := &Client{
		token:  "", // no token
		url:    ts.URL,
		client: http.DefaultClient,
	}

	_, err := client.CoreVersion()
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

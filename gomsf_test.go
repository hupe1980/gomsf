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

	rpc := rpc.NewRPC(http.DefaultClient, ts.URL)

	c := &Client{
		rpc:  rpc,
		Auth: &AuthManager{rpc: rpc},
	}

	err := c.Login("user", "pass")
	assert.NoError(t, err)
	assert.Equal(t, true, c.Authenticated())
}

func TestLogout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = msgpack.NewEncoder(w).Encode(&rpc.AuthLogoutRes{
			Result: "success",
		})
	}))
	defer ts.Close()

	rpc := rpc.NewRPC(http.DefaultClient, ts.URL)
	rpc.SetToken("token")

	c := &Client{
		rpc:  rpc,
		Auth: &AuthManager{rpc: rpc},
	}

	err := c.Logout()
	assert.NoError(t, err)
	assert.Equal(t, false, c.Authenticated())
}

func TestNoAuthError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	rpc := rpc.NewRPC(http.DefaultClient, ts.URL)

	c := &Client{
		rpc:  rpc,
		Auth: &AuthManager{rpc: rpc},
		Core: &CoreManager{rpc: rpc},
	}

	_, err := c.Core.Version()
	assert.Error(t, err)
	assert.Equal(t, "client not authenticated", err.Error())
}

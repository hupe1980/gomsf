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

	msf := &MSF{
		rpc:  rpc,
		Auth: &AuthManager{rpc: rpc},
	}

	err := msf.Login("user", "pass")
	assert.NoError(t, err)
	assert.Equal(t, true, msf.Authenticated())
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

	msf := &MSF{
		rpc:  rpc,
		Auth: &AuthManager{rpc: rpc},
	}

	err := msf.Logout()
	assert.NoError(t, err)
	assert.Equal(t, false, msf.Authenticated())
}

func TestNoAuthError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	rpc := rpc.NewRPC(http.DefaultClient, ts.URL)

	msf := &MSF{
		rpc:  rpc,
		Auth: &AuthManager{rpc: rpc},
		Core: &CoreManager{rpc: rpc},
	}

	_, err := msf.Core.Version()
	assert.Error(t, err)
	assert.Equal(t, "client not authenticated", err.Error())
}

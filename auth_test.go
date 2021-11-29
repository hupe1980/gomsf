package gomsf

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vmihailenco/msgpack/v5"
)

func TestLogin(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = msgpack.NewEncoder(w).Encode(&LoginRes{
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

	err := client.Login("user", "pass")
	assert.NoError(t, err)
	assert.Equal(t, true, client.HasToken())
}

func TestLogout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = msgpack.NewEncoder(w).Encode(&LogoutRes{
			Result: "success",
		})
	}))
	defer ts.Close()

	client := &Client{
		token:  "token",
		url:    ts.URL,
		client: http.DefaultClient,
	}

	err := client.Logout()
	assert.NoError(t, err)
	assert.Equal(t, false, client.HasToken())
}

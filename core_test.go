package gomsf

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vmihailenco/msgpack/v5"
)

func TestCoreVersion(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = msgpack.NewEncoder(w).Encode(&CoreVersionRes{
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

	result, err := client.CoreVersion()
	assert.NoError(t, err)
	assert.Equal(t, "4711", result.Version)
	assert.Equal(t, "ruby", result.Ruby)
	assert.Equal(t, "api", result.API)
}

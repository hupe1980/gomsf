package gomsf

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"time"

	"github.com/hupe1980/gomsf/rpc"
	"github.com/vmihailenco/msgpack/v5"
)

type Client struct {
	user       string
	pass       string
	token      string
	url        string
	apiVersion string
	client     *http.Client
	rpc        *rpc.RPC
	Auth       *AuthManager
	Consoles   *ConsoleManager
	Core       *CoreManager
	Health     *HealthManager
	Plugins    *PluginManager
	Jobs       *JobManager
}

type ClientOptions struct {
	Timeout         time.Duration
	ProxyURL        string
	TLSClientConfig *tls.Config
	Token           string
	SSL             bool
	APIVersion      string
}

func New(address string, optFns ...func(o *ClientOptions)) (*Client, error) {
	options := ClientOptions{
		Token:           "",
		SSL:             true,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec //unknown ca
		APIVersion:      "1.0",
	}
	for _, fn := range optFns {
		fn(&options)
	}

	client, err := newHTTPClient(options)
	if err != nil {
		return nil, err
	}

	protocol := "http"
	if options.SSL {
		protocol = "https"
	}

	c := &Client{
		apiVersion: options.APIVersion,
		url:        fmt.Sprintf("%s://%s/api/%s", protocol, address, options.APIVersion),
		client:     client,
	}

	c.rpc = rpc.NewRPC(c)

	c.Auth = &AuthManager{rpc: c.rpc}
	c.Consoles = &ConsoleManager{rpc: c.rpc}
	c.Core = &CoreManager{rpc: c.rpc}
	c.Health = &HealthManager{rpc: c.rpc}
	c.Plugins = &PluginManager{rpc: c.rpc}
	c.Jobs = &JobManager{rpc: c.rpc}

	return c, nil
}

func (c *Client) Authenticated() bool {
	return c.token != ""
}

func (c *Client) APIVersion() string {
	return c.apiVersion
}

func (c *Client) Call(req, res interface{}) error {
	return c.call(req, res)
}

func (c *Client) Token() string {
	return c.token
}

func (c *Client) HealthCheck() error {
	return c.Health.Check()
}

// Login logs in by calling the 'auth.login' API. The authentication token will expire after 5
// minutes, but will automatically be rewnewed when you make a new RPC request.
func (c *Client) Login(user, pass string) error {
	token, err := c.Auth.Login(user, pass)
	if err != nil {
		return err
	}

	c.user = user
	c.pass = pass
	c.token = token

	return nil
}

// ReLogin attempts to login again with the last known user name and password
func (c *Client) ReLogin() error {
	return c.Login(c.user, c.pass)
}

func (c *Client) Logout() error {
	err := c.Auth.Logout()
	if err != nil {
		return err
	}

	c.user = ""
	c.pass = ""
	c.token = ""

	return nil
}

func (c *Client) call(req, res interface{}) error {
	method := rpcMethod(req)
	if method != "auth.login" && method != "health.check" {
		if c.token == "" {
			return errors.New("client not authenticated")
		}
	}

	buf := new(bytes.Buffer)
	enc := msgpack.NewEncoder(buf)
	enc.UseArrayEncodedStructs(true)

	if err := enc.Encode(req); err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(context.Background(), "POST", c.url, buf)
	if err != nil {
		return err
	}

	request.Header.Add("Content-Type", "binary/message-pack")

	response, err := c.client.Do(request)
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

func newHTTPClient(options ClientOptions) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = options.TLSClientConfig

	if options.ProxyURL != "" {
		proxyURL, err := url.Parse(options.ProxyURL)
		if err != nil {
			return nil, err
		}

		transport.Proxy = http.ProxyURL(proxyURL)
	}

	return &http.Client{
		Timeout:   options.Timeout,
		Transport: transport,
	}, nil
}

func rpcMethod(req interface{}) string {
	stype := reflect.ValueOf(req).Elem()
	field := stype.FieldByName("Method")

	if field.IsValid() {
		return field.String()
	}

	return ""
}

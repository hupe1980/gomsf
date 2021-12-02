package gomsf

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/hupe1980/gomsf/rpc"
)

type Client struct {
	user       string
	pass       string
	apiVersion string
	rpc        *rpc.RPC
	Auth       *AuthManager
	Consoles   *ConsoleManager
	Core       *CoreManager
	Health     *HealthManager
	Plugins    *PluginManager
	Jobs       *JobManager
	Module     *ModuleManager
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

	http, err := newHTTPClient(options)
	if err != nil {
		return nil, err
	}

	url := generateURL(address, options.SSL, options.APIVersion)

	rpc := rpc.NewRPC(http, url)

	if options.Token != "" {
		rpc.SetToken(options.Token)
	}

	c := &Client{
		apiVersion: options.APIVersion,
		rpc:        rpc,
		Auth:       &AuthManager{rpc: rpc},
		Consoles:   &ConsoleManager{rpc: rpc},
		Core:       &CoreManager{rpc: rpc},
		Health:     &HealthManager{rpc: rpc},
		Jobs:       &JobManager{rpc: rpc},
		Module:     &ModuleManager{rpc: rpc},
		Plugins:    &PluginManager{rpc: rpc},
	}

	return c, nil
}

func (c *Client) Authenticated() bool {
	return c.rpc.Token() != ""
}

func (c *Client) APIVersion() string {
	return c.apiVersion
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

	c.rpc.SetToken(token)

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

	c.rpc.SetToken("")

	return nil
}

func generateURL(address string, ssl bool, apiVersion string) string {
	protocol := "http"
	if ssl {
		protocol = "https"
	}

	return fmt.Sprintf("%s://%s/api/%s", protocol, address, apiVersion)
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

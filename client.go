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

	"github.com/vmihailenco/msgpack/v5"
)

type Client struct {
	user       string
	pass       string
	token      string
	url        string
	apiVersion string
	client     *http.Client
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

	return c, nil
}

func (c *Client) HasToken() bool {
	return c.token != ""
}

func (c *Client) APIVersion() string {
	return c.apiVersion
}

func (c *Client) call(req, res interface{}) error {
	method := rpcMethod(req)
	if method != "auth.login" && method != "health.check" {
		if c.token == "" {
			return errors.New("client not authenticated")
		}
	}

	buf := new(bytes.Buffer)
	if err := msgpack.NewEncoder(buf).Encode(req); err != nil {
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

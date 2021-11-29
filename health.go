package gomsf

type HealthCheckReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
}

// HealthCheck returns whether the service is currently healthy and ready to accept requests
func (c *Client) HealthCheck() error {
	req := &HealthCheckReq{
		Method: "health.check",
	}

	if err := c.call(req, nil); err != nil {
		return err
	}

	return nil
}

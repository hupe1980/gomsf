package rpc

type health struct {
	client Client
}

type HealthCheckReq struct {
	Method string
}

// Check returns whether the service is currently healthy and ready to accept requests
func (h *health) Check() error {
	req := &HealthCheckReq{
		Method: "health.check",
	}

	if err := h.client.Call(req, nil); err != nil {
		return err
	}

	return nil
}

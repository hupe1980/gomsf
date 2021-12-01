package rpc

type health struct {
	rpc *RPC
}

type HealthCheckReq struct {
	Method string
}

// Check returns whether the service is currently healthy and ready to accept requests
func (h *health) Check() error {
	req := &HealthCheckReq{
		Method: "health.check",
	}

	if err := h.rpc.Call(req, nil); err != nil {
		return err
	}

	return nil
}

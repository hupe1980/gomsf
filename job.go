package gomsf

type jobInfoReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
	JobId    string
}

type jobInfoRes struct {
	JobID     int                    `msgpack:"jid"`
	Name      string                 `msgpack:"name"`
	StartTime int                    `msgpack:"start_time"`
	UriPath   interface{}            `msgpack:"uripath,omitempty"`
	Datastore map[string]interface{} `msgpack:"datastore,omitempty"`
}

// JobInfo returns information about a job
func (c *Client) JobInfo(jobID string) (*jobInfoRes, error) {
	req := &jobInfoReq{
		Method: "job.info",
		Token:  c.token,
		JobId:  jobID,
	}
	var res *jobInfoRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type jobListReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
}

type jobListRes map[string]string

// JobList returns a list of jobs
func (c *Client) JobList() (*jobListRes, error) {
	req := &jobListReq{
		Method: "job.list",
		Token:  c.token,
	}
	var res *jobListRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

type jobStopReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused
	Method   string
	Token    string
	JobID    string
}

type jobStopRes struct {
	Result string `msgpack:"result"`
}

// JobStop stops a job
func (c *Client) JobStop(jobID string) (*jobStopRes, error) {
	req := &jobStopReq{
		Method: "job.stop",
		Token:  c.token,
		JobID:  jobID,
	}
	var res *jobStopRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

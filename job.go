package gomsf

type JobInfoReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
	JobID    string
}

type JobInfoRes struct {
	JobID     int                    `msgpack:"jid"`
	Name      string                 `msgpack:"name"`
	StartTime int                    `msgpack:"start_time"`
	URIPath   interface{}            `msgpack:"uripath,omitempty"`
	Datastore map[string]interface{} `msgpack:"datastore,omitempty"`
}

// JobInfo returns information about a job
func (c *Client) JobInfo(jobID string) (*JobInfoRes, error) {
	req := &JobInfoReq{
		Method: "job.info",
		Token:  c.token,
		JobID:  jobID,
	}

	var res *JobInfoRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type JobListReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
}

type JobListRes map[string]string

// JobList returns a list of jobs
func (c *Client) JobList() (*JobListRes, error) {
	req := &JobListReq{
		Method: "job.list",
		Token:  c.token,
	}

	var res *JobListRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type JobStopReq struct {
	_msgpack struct{} `msgpack:",asArray"` //nolint:structcheck,unused //msgpack internal
	Method   string
	Token    string
	JobID    string
}

type JobStopRes struct {
	Result string `msgpack:"result"`
}

// JobStop stops a job
func (c *Client) JobStop(jobID string) (*JobStopRes, error) {
	req := &JobStopReq{
		Method: "job.stop",
		Token:  c.token,
		JobID:  jobID,
	}

	var res *JobStopRes
	if err := c.call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

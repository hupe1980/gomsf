package rpc

type job struct {
	client Client
}

type JobInfoReq struct {
	Method string
	Token  string
	JobID  string
}

type JobInfoRes struct {
	JobID     int                    `msgpack:"jid"`
	Name      string                 `msgpack:"name"`
	StartTime int                    `msgpack:"start_time"`
	URIPath   interface{}            `msgpack:"uripath,omitempty"`
	Datastore map[string]interface{} `msgpack:"datastore,omitempty"`
}

// Info returns information about a job
func (j *job) Info(jobID string) (*JobInfoRes, error) {
	req := &JobInfoReq{
		Method: "job.info",
		Token:  j.client.Token(),
		JobID:  jobID,
	}

	var res *JobInfoRes
	if err := j.client.Call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type JobListReq struct {
	Method string
	Token  string
}

type JobListRes map[string]string

// List returns a list of jobs
func (j *job) List() (*JobListRes, error) {
	req := &JobListReq{
		Method: "job.list",
		Token:  j.client.Token(),
	}

	var res *JobListRes
	if err := j.client.Call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type JobStopReq struct {
	Method string
	Token  string
	JobID  string
}

type JobStopRes struct {
	Result Result `msgpack:"result"`
}

// Stop stops a job
func (j *job) Stop(jobID string) (*JobStopRes, error) {
	req := &JobStopReq{
		Method: "job.stop",
		Token:  j.client.Token(),
		JobID:  jobID,
	}

	var res *JobStopRes
	if err := j.client.Call(req, &res); err != nil {
		return nil, err
	}

	return res, nil
}

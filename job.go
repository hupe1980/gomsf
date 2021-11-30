package gomsf

import (
	"fmt"

	"github.com/hupe1980/gomsf/rpc"
)

type JobManager struct {
	rpc *rpc.RPC
}

func (jm *JobManager) List() (*rpc.JobListRes, error) {
	return jm.rpc.Job.List()
}

func (jm *JobManager) Stop(jobID string) error {
	r, err := jm.rpc.Job.Stop(jobID)
	if err != nil {
		return err
	}

	if r.Result == rpc.FAILURE {
		return fmt.Errorf("cannot stop job %s", jobID)
	}

	return nil
}

func (jm *JobManager) Info(jobID string) (*rpc.JobInfoRes, error) {
	return jm.rpc.Job.Info(jobID)
}

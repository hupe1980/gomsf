package gomsf

import (
	"fmt"
	"strings"

	"github.com/hupe1980/gomsf/rpc"
)

type session struct {
	id  int
	rpc *rpc.RPC
}

func (s *session) Stop() {
	// TODO
}

func (s *session) Modules() ([]string, error) {
	r, err := s.rpc.Session.CompatibleModules(s.id)
	if err != nil {
		return nil, err
	}

	return r.Modules, nil
}

type MeterpreterSession struct {
	session
}

func (ms *MeterpreterSession) Read() (string, error) {
	r, err := ms.rpc.Session.MeterpreterRead(ms.id)
	if err != nil {
		return "", err
	}

	return r.Data, nil
}

func (ms *MeterpreterSession) Write(command string) error {
	if !strings.HasSuffix(command, "\n") {
		command = fmt.Sprintf("%s\n", command)
	}

	r, err := ms.rpc.Session.MeterpreterWrite(ms.id, command)
	if err != nil {
		return err
	}

	if r.Result == rpc.FAILURE {
		return fmt.Errorf("cannot write command %s to session %d", command, ms.id)
	}

	return nil
}

type SessionManager struct {
}

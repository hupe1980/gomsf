package gomsf

import (
	"errors"

	"github.com/hupe1980/gomsf/rpc"
)

type AuthManager struct {
	rpc *rpc.RPC
}

func (am *AuthManager) Login(user, pass string) (string, error) {
	r, err := am.rpc.Auth.Login(user, pass)
	if err != nil {
		return "", err
	}

	if r.Result == rpc.FAILURE || r.Token == "" {
		return "", errors.New("authentication failed")
	}

	return r.Token, nil
}

func (am *AuthManager) Logout() error {
	r, err := am.rpc.Auth.Logout()
	if err != nil {
		return err
	}

	if r.Result == rpc.FAILURE {
		return errors.New("logout failed")
	}

	return nil
}

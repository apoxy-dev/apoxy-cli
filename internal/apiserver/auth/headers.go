// Package auth contains APIServer authentication helpers.
package auth

import (
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/anonymous"
	"k8s.io/apiserver/pkg/authentication/request/headerrequest"
	"k8s.io/apiserver/pkg/authentication/request/union"
)

const (
	UserHeaderKey  = "X-Remote-User"
	GroupHeaderKey = "X-Remote-Group"
	ExtraHeaderKey = "X-Remote-Extra-"
)

// NewHeaderAuthenticator returns a new authenticator.Request that authenticates
// requests based on the X-Remote-User, X-Remote-Group, and X-Remote-Extra headers.
func NewHeaderAuthenticator() (authenticator.Request, error) {
	rhAuth, err := headerrequest.New(
		[]string{UserHeaderKey},
		[]string{GroupHeaderKey},
		[]string{ExtraHeaderKey},
	)
	if err != nil {
		return nil, err
	}
	return union.New(
		rhAuth,
		anonymous.NewAuthenticator(),
	), nil
}

package auth

import (
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/x509"
)

// NewX509Authenticator creates a new authenticator that authenticates requests
// based on the provided client certificate.
func NewX509Authenticator(clientCAPath string) (authenticator.Request, error) {
	vOpts, err := x509.NewStaticVerifierFromFile(clientCAPath)
	if err != nil {
		return nil, err
	}
	return x509.NewDynamic(vOpts, x509.CommonNameUserConversion), nil
}

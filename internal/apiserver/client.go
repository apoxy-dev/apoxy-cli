package apiserver

import (
	"fmt"

	"k8s.io/client-go/rest"
)

// NewLocalClientConfig returns a new local client configuration.
func NewLocalClientConfig(hostname string) *rest.Config {
	return &rest.Config{
		QPS:  -1,
		Host: fmt.Sprintf("https://%s:443", hostname),
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: true,
		},
	}
}

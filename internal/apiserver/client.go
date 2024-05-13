package apiserver

import "k8s.io/client-go/rest"

// NewLocalClientConfig returns a new local client configuration.
func NewLocalClientConfig() *rest.Config {
	return &rest.Config{
		QPS:  -1,
		Host: "https://localhost:443",
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: true,
		},
	}
}

package apiserver

import (
	"fmt"

	"k8s.io/client-go/rest"
)

// ClientOption is a set of options for the client.
type ClientOption func(*clientOptions)

type clientOptions struct {
	host      string
	tlsConfig rest.TLSClientConfig
}

func defaultClientOptions() *clientOptions {
	return &clientOptions{
		host: "localhost:443",
		tlsConfig: rest.TLSClientConfig{
			Insecure: true,
		},
	}
}

// WithClientHost sets the host for the client.
// The default host is "localhost:443".
func WithClientHost(host string) ClientOption {
	return func(o *clientOptions) {
		o.host = host
	}
}

// WithClientTLSConfig sets the TLS configuration for the client.
// If not set, the client will use an insecure configuration.
func WithClientTLSConfig(tlsConfig rest.TLSClientConfig) ClientOption {
	return func(o *clientOptions) {
		o.tlsConfig = tlsConfig
	}
}

// NewClientConfig returns a new local client configuration.
func NewClientConfig(opts ...ClientOption) *rest.Config {
	sOpts := defaultClientOptions()
	for _, opt := range opts {
		opt(sOpts)
	}
	return &rest.Config{
		QPS:             -1,
		Host:            fmt.Sprintf("https://%s", sOpts.host),
		TLSClientConfig: sOpts.tlsConfig,
	}
}

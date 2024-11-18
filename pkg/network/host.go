package network

import (
	"context"
	"net"
)

var _ Network = (*HostNetwork)(nil)

type HostNetwork struct{}

// Host returns a network implementation that uses the host's network stack.
func Host() *HostNetwork {
	return &HostNetwork{}
}

func (n *HostNetwork) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return net.Dial(network, addr)
}

func (n *HostNetwork) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	return (&net.Resolver{}).LookupHost(ctx, host)
}

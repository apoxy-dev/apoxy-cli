package network

import (
	"context"
	"net"
)

var _ Network = (*LoopbackNetwork)(nil)

type LoopbackNetwork struct{}

// Loopback returns a network that only connects to localhost.
func Loopback() *LoopbackNetwork {
	return &LoopbackNetwork{}
}

func (n *LoopbackNetwork) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	return net.Dial(network, net.JoinHostPort("localhost", port))
}

func (n *LoopbackNetwork) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	return (&net.Resolver{}).LookupHost(ctx, "localhost")
}

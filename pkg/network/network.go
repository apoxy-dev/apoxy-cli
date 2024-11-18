package network

import (
	"context"
	"net"
)

// Network is a simple network abstraction.
type Network interface {
	// DialContext connects to the address on the named network using the provided context.
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	// LookupContextHost looks up the given host using the local resolver.
	// It returns a slice of that host's addresses.
	LookupContextHost(ctx context.Context, host string) ([]string, error)
}

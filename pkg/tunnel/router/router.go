package router

import (
	"context"
	"net/netip"

	"github.com/apoxy-dev/apoxy-cli/pkg/connip"
)

// Router is an interface for managing tunnel routing.
type Router interface {
	// Start initializes the router and starts forwarding traffic.
	// It's a blocking call that should be run in a separate goroutine.
	Start(ctx context.Context) error

	// AddPeer adds a peer route to the tunnel.
	AddPeer(peer netip.Prefix, conn connip.Connection) error

	// RemovePeer removes a peer route from the tunnel.
	RemovePeer(peer netip.Prefix) error

	// Close releases any resources associated with the router.
	Close() error
}

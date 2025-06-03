package router

import (
	"context"
	"io"
	"net/netip"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
)

// Router is an interface for managing tunnel routing.
type Router interface {
	io.Closer

	// Start initializes the router and starts forwarding traffic.
	// It's a blocking call that should be run in a separate goroutine.
	Start(ctx context.Context) error

	// AddPeer adds a peer route to the tunnel. Returns the list of IP prefixes
	// to be advertised to the peer (if none returned, no prefixes should be advertised).
	AddPeer(peer netip.Prefix, conn connection.Connection) (privAddr netip.Addr, routes []netip.Prefix, err error)

	// RemovePeer removes a peer route from the tunnel identified by the given prefix.
	RemovePeer(peer netip.Prefix) error

	// LocalAddresses returns the list of local addresses that are assigned to the router.
	LocalAddresses() ([]netip.Prefix, error)
}

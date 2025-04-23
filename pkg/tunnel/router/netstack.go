package router

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/apoxy-dev/apoxy-cli/pkg/connip"
	"github.com/apoxy-dev/apoxy-cli/pkg/netstack"
)

var (
	_ Router = (*NetstackRouter)(nil)
)

// NetstackRouter implements Router using a userspace network stack.
// This is a placeholder implementation that will be expanded in the future.
type NetstackRouter struct {
	tunDev tun.Device
	mux    *connip.MuxedConnection
}

// NewNetstackRouter creates a new netstack-based tunnel router.
func NewNetstackRouter() (*NetstackRouter, error) {
	// Create a virtual TUN device for the userspace network stack
	tunDev, err := netstack.NewTunDevice([]netip.Prefix{}, nil, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create virtual TUN device: %w", err)
	}

	return &NetstackRouter{
		tunDev: tunDev,
		mux:    connip.NewMuxedConnection(),
	}, nil
}

// Start initializes the router and starts forwarding traffic.
func (r *NetstackRouter) Start(ctx context.Context) error {
	slog.Info("Starting netstack TUN muxer")
	defer slog.Debug("Netstack TUN muxer stopped")

	// Create error group with context
	g, gctx := errgroup.WithContext(ctx)

	// Setup cleanup handler
	g.Go(func() error {
		<-gctx.Done()
		slog.Debug("Closing netstack TUN device")
		if err := r.tunDev.Close(); err != nil {
			return fmt.Errorf("failed to close netstack TUN device: %w", err)
		}
		return nil
	})

	// Start the splicing operation
	g.Go(func() error {
		return connip.Splice(r.tunDev, r.mux)
	})

	return g.Wait()
}

// AddPeer adds a peer route to the tunnel.
func (r *NetstackRouter) AddPeer(peer netip.Prefix, conn connip.Connection) ([]netip.Prefix, error) {
	slog.Debug("Adding route in netstack", slog.String("prefix", peer.String()))
	// For now, we'll just log the request but not actually implement routing
	// This will be expanded in the future
	return nil, fmt.Errorf("netstack router route addition not yet implemented")
}

// RemovePeer removes a peer route from the tunnel.
func (r *NetstackRouter) RemovePeer(peer netip.Prefix) error {
	slog.Debug("Removing route in netstack", slog.String("prefix", peer.String()))
	// For now, we'll just log the request but not actually implement routing
	// This will be expanded in the future
	return fmt.Errorf("netstack router route removal not yet implemented")
}

// Close releases any resources associated with the router.
func (r *NetstackRouter) Close() error {
	if r.tunDev != nil {
		return r.tunDev.Close()
	}
	return nil
}

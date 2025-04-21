//go:build linux

package router

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/apoxy-dev/apoxy-cli/pkg/connip"
	"github.com/apoxy-dev/apoxy-cli/pkg/netstack"
)

// NetlinkRouter implements Router using Linux's netlink subsystem.
type NetlinkRouter struct {
	tunName string
	tunDev  tun.Device
	link    netlink.Link
	mux     *connip.MuxedConnection
}

// NewNetlinkRouter creates a new netlink-based tunnel router.
func NewNetlinkRouter() (*NetlinkRouter, error) {
	// Create tun device
	tunDev, err := tun.CreateTUN("tun0", netstack.IPv6MinMTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN interface: %w", err)
	}

	// Get the actual tun name (may differ from requested name)
	actualTunName, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("failed to get TUN interface name: %w", err)
	}

	// Get link by name
	link, err := netlink.LinkByName(actualTunName)
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("failed to get TUN interface: %w", err)
	}

	// Bring up the interface
	if err := netlink.LinkSetUp(link); err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("failed to bring up TUN interface: %w", err)
	}

	return &NetlinkRouter{
		tunName: actualTunName,
		tunDev:  tunDev,
		link:    link,
		mux:     connip.NewMuxedConnection(),
	}, nil
}

// Start initializes the router and starts forwarding traffic.
func (r *NetlinkRouter) Start(ctx context.Context) error {
	slog.Info("Starting TUN muxer")
	defer slog.Debug("TUN muxer stopped")

	// Create error group with context
	g, gctx := errgroup.WithContext(ctx)

	// Setup cleanup handler
	g.Go(func() error {
		<-gctx.Done()
		slog.Debug("Closing TUN device")
		if err := r.tunDev.Close(); err != nil {
			return fmt.Errorf("failed to close TUN device: %w", err)
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
func (r *NetlinkRouter) AddPeer(peer netip.Prefix, conn connip.Connection) error {
	slog.Debug("Adding route", slog.String("prefix", peer.String()))

	route := &netlink.Route{
		LinkIndex: r.link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   peer.Addr().AsSlice(),
			Mask: net.CIDRMask(peer.Bits(), 128),
		},
		Scope: netlink.SCOPE_LINK,
	}
	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}

	r.mux.AddConnection(peer, conn)

	return nil
}

// RemovePeer removes a peer route from the tunnel.
func (r *NetlinkRouter) RemovePeer(peer netip.Prefix) error {
	slog.Debug("Removing route", slog.String("prefix", peer.String()))

	if err := r.mux.RemoveConnection(peer); err != nil {
		slog.Error("failed to remove connection", err)
	}

	route := &netlink.Route{
		LinkIndex: r.link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   peer.Addr().AsSlice(),
			Mask: net.CIDRMask(peer.Bits(), 128),
		},
		Scope: netlink.SCOPE_LINK,
	}
	if err := netlink.RouteDel(route); err != nil {
		return fmt.Errorf("failed to remove route: %w", err)
	}

	return nil
}

// GetMuxedConnection returns the muxed connection for adding/removing connections.
func (r *NetlinkRouter) GetMuxedConnection() *connip.MuxedConnection {
	return r.mux
}

// Close releases any resources associated with the router.
func (r *NetlinkRouter) Close() error {
	if r.tunDev != nil {
		return r.tunDev.Close()
	}
	return nil
}

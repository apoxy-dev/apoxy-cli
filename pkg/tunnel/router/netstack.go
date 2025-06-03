package router

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/socksproxy"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
	"github.com/dpeckett/network"
)

var (
	_ Router = (*NetstackRouter)(nil)
)

// NetstackRouter implements Router using a userspace network stack.
type NetstackRouter struct {
	tunDev          *netstack.TunDevice
	mux             *connection.MuxedConnection
	proxy           *socksproxy.ProxyServer
	localAddresses  []netip.Prefix
	resolveConf     *network.ResolveConfig
	socksListenAddr string
	closeOnce       sync.Once
}

// NewNetstackRouter creates a new netstack-based tunnel router.
func NewNetstackRouter(opts ...Option) (*NetstackRouter, error) {
	options := defaultOptions()
	for _, opt := range opts {
		opt(options)
	}

	tunDev, err := netstack.NewTunDevice(options.localAddresses, options.pcapPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create virtual TUN device: %w", err)
	}

	proxy := socksproxy.NewServer(options.socksListenAddr, tunDev.Network(options.resolveConf), network.Host())

	return &NetstackRouter{
		tunDev:          tunDev,
		mux:             connection.NewMuxedConnection(),
		proxy:           proxy,
		localAddresses:  options.localAddresses,
		resolveConf:     options.resolveConf,
		socksListenAddr: options.socksListenAddr,
	}, nil
}

// Start initializes the router and starts forwarding traffic.
func (r *NetstackRouter) Start(ctx context.Context) error {
	slog.Info("Starting netstack TUN muxer")
	defer slog.Debug("Netstack TUN muxer stopped")

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-gctx.Done()
		slog.Debug("Closing router")
		return r.Close()
	})

	g.Go(func() error {
		return connection.Splice(r.tunDev, r.mux)
	})

	_, socksListenPortStr, err := net.SplitHostPort(r.socksListenAddr)
	if err != nil {
		return fmt.Errorf("failed to parse SOCKS listen address: %w", err)
	}

	socksListenPort, err := strconv.Atoi(socksListenPortStr)
	if err != nil {
		return fmt.Errorf("failed to parse SOCKS listen port: %w", err)
	}

	slog.Info("Forwarding all inbound traffic to loopback interface")

	if err := r.tunDev.ForwardTo(ctx, network.Filtered(&network.FilteredNetworkConfig{
		DeniedPorts: []uint16{uint16(socksListenPort)},
		Upstream:    network.Loopback(),
	})); err != nil {
		return fmt.Errorf("failed to forward to loopback: %w", err)
	}

	slog.Info("Starting SOCKS5 proxy", slog.String("listenAddr", r.socksListenAddr))

	g.Go(func() error {
		if err := r.proxy.ListenAndServe(ctx); err != nil {
			slog.Error("SOCKS proxy error", slog.String("error", err.Error()))
		}

		return nil
	})

	return g.Wait()
}

// AddPeer adds a peer route to the tunnel.
func (r *NetstackRouter) AddPeer(peer netip.Prefix, conn connection.Connection) (netip.Addr, []netip.Prefix, error) {
	r.mux.AddConnection(peer, conn)
	return peer.Addr(), r.localAddresses, nil
}

// RemovePeer removes a peer route from the tunnel.
func (r *NetstackRouter) RemovePeer(peer netip.Prefix) error {
	if err := r.mux.RemoveConnection(peer); err != nil {
		slog.Error("failed to remove connection", slog.Any("error", err))
	}

	return nil
}

// GetMuxedConnection returns the muxed connection for adding/removing connections.
func (r *NetstackRouter) GetMuxedConnection() *connection.MuxedConnection {
	return r.mux
}

// Close releases any resources associated with the router.
func (r *NetstackRouter) Close() error {
	var firstErr error
	r.closeOnce.Do(func() {
		if err := r.proxy.Close(); err != nil {
			slog.Error("Failed to close SOCKS proxy", slog.Any("error", err))
			if firstErr == nil {
				firstErr = fmt.Errorf("failed to close SOCKS proxy: %w", err)
			}
		}

		if err := r.mux.Close(); err != nil {
			slog.Error("Failed to close muxed connection", slog.Any("error", err))
			if firstErr == nil {
				firstErr = fmt.Errorf("failed to close muxed connection: %w", err)
			}
		}

		if err := r.tunDev.Close(); err != nil {
			slog.Error("Failed to close TUN device", slog.Any("error", err))
			if firstErr == nil {
				firstErr = fmt.Errorf("failed to close TUN device: %w", err)
			}
		}
	})
	return firstErr
}

// LocalAddresses returns the list of local addresses that are assigned to the router.
func (r *NetstackRouter) LocalAddresses() ([]netip.Prefix, error) {
	return r.tunDev.LocalAddresses()
}

package tunnel

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"

	"github.com/dpeckett/network"
	"github.com/google/uuid"

	"github.com/apoxy-dev/apoxy-cli/pkg/connip"
	"github.com/apoxy-dev/apoxy-cli/pkg/socksproxy"
)

type TunnelClientOption func(*tunnelClientOptions)

type tunnelClientOptions struct {
	serverAddr         string
	insecureSkipVerify bool
	uuid               uuid.UUID
	authToken          string
	pcapPath           string
	rootCAs            *x509.CertPool
	socksListenAddr    string
}

func defaultClientOptions() *tunnelClientOptions {
	return &tunnelClientOptions{
		serverAddr:      "localhost:9443",
		socksListenAddr: "localhost:1080",
	}
}

// WithServerAddr sets the server address that the tunnel client will connect to.
// The address should be in the format "host:port".
func WithServerAddr(addr string) TunnelClientOption {
	return func(o *tunnelClientOptions) {
		o.serverAddr = addr
	}
}

// WithInsecureSkipVerify skips TLS certificate verification of the server.
func WithInsecureSkipVerify(skip bool) TunnelClientOption {
	return func(o *tunnelClientOptions) {
		o.insecureSkipVerify = skip
	}
}

// WithUUID sets the UUID for the tunnel client.
func WithUUID(uuid uuid.UUID) TunnelClientOption {
	return func(o *tunnelClientOptions) {
		o.uuid = uuid
	}
}

// WithAuthToken sets the authentication token for the tunnel client.
func WithAuthToken(token string) TunnelClientOption {
	return func(o *tunnelClientOptions) {
		o.authToken = token
	}
}

// WithPcapPath sets the optional path to a packet capture file for the tunnel client.
func WithPcapPath(path string) TunnelClientOption {
	return func(o *tunnelClientOptions) {
		o.pcapPath = path
	}
}

// WithRootCAs sets the optional root CA certificates for TLS verification.
func WithRootCAs(caCerts *x509.CertPool) TunnelClientOption {
	return func(o *tunnelClientOptions) {
		o.rootCAs = caCerts
	}
}

// WithSocksListenAddr sets the listen address for the local SOCKS5 proxy server.
func WithSocksListenAddr(addr string) TunnelClientOption {
	return func(o *tunnelClientOptions) {
		o.socksListenAddr = addr
	}
}

type TunnelClient struct {
	options   *tunnelClientOptions
	transport *connip.ClientTransport
	proxy     *socksproxy.ProxyServer

	tunnelCtx       context.Context
	tunnelCtxCancel context.CancelFunc
}

// NewTunnelClient creates a new SOCKS5 proxy and loopback reverse proxy,
// that forwards and receives traffic via QUIC tunnels.
func NewTunnelClient(opts ...TunnelClientOption) (*TunnelClient, error) {
	options := defaultClientOptions()
	for _, opt := range opts {
		opt(options)
	}

	if options.uuid == uuid.Nil {
		return nil, fmt.Errorf("uuid is required")
	}

	if options.authToken == "" {
		return nil, fmt.Errorf("auth token is required")
	}

	// Create the transport layer for the tunnel client.
	transport := connip.NewClientTransport(&connip.ClientConfig{
		UUID:               options.uuid,
		AuthToken:          options.authToken,
		PcapPath:           options.pcapPath,
		RootCAs:            options.rootCAs,
		InsecureSkipVerify: options.insecureSkipVerify,
	})

	proxy := socksproxy.NewServer(options.socksListenAddr, transport, network.Host())

	return &TunnelClient{
		options:   options,
		transport: transport,
		proxy:     proxy,
	}, nil
}

// Start establishes a connection to the server and begins forwarding traffic.
func (c *TunnelClient) Start(ctx context.Context) error {
	c.tunnelCtx, c.tunnelCtxCancel = context.WithCancel(ctx)

	// Connect to the server using the transport layer.
	if err := c.transport.Connect(ctx, c.options.serverAddr); err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}

	_, socksListenPortStr, err := net.SplitHostPort(c.options.socksListenAddr)
	if err != nil {
		return fmt.Errorf("failed to parse SOCKS listen address: %w", err)
	}

	socksListenPort, err := strconv.Atoi(socksListenPortStr)
	if err != nil {
		return fmt.Errorf("failed to parse SOCKS listen port: %w", err)
	}

	slog.Info("Forwarding all inbound traffic to loopback interface")

	// Forward all inbound traffic to the loopback interface.
	// This allows the tunnel client to act as a reverse proxy.
	if err := c.transport.FowardTo(c.tunnelCtx, network.Filtered(&network.FilteredNetworkConfig{
		// Otherwise we could be DoS'd by a network loop.
		DeniedPorts: []uint16{uint16(socksListenPort)},
		Upstream:    network.Loopback(),
		AllowedDestinations: []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/24"),
			netip.MustParsePrefix("::1/128"),
		},
	})); err != nil {
		return fmt.Errorf("failed to forward to loopback: %w", err)
	}

	slog.Info("Starting SOCKS5 proxy", slog.String("listenAddr", c.options.socksListenAddr))

	// Start the SOCKS5 proxy for forwarding outbound traffic.
	go func() {
		if err := c.proxy.ListenAndServe(c.tunnelCtx); err != nil {
			slog.Error("SOCKS proxy error", slog.String("error", err.Error()))
		}
	}()

	return nil
}

// Stop closes the tunnel client and stops forwarding traffic.
func (t *TunnelClient) Stop() error {
	// Stop any background tasks (and the SOCKS5 proxy).
	if t.tunnelCtxCancel != nil {
		t.tunnelCtxCancel()
	}

	// Close the transport layer.
	if t.transport != nil {
		if err := t.transport.Close(); err != nil {
			return fmt.Errorf("failed to close transport: %w", err)
		}
	}

	return nil
}

// Get the local addresses assigned to the tunnel client.
func (c *TunnelClient) LocalAddresses() ([]netip.Prefix, error) {
	return c.transport.LocalAddresses()
}

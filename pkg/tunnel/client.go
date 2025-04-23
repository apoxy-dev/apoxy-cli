package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dpeckett/network"
	"github.com/google/uuid"
	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"github.com/apoxy-dev/apoxy-cli/pkg/netstack"
	"github.com/apoxy-dev/apoxy-cli/pkg/socksproxy"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel/connection"
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

const ApplicationCodeOK quic.ApplicationErrorCode = 0x0

type TunnelClient struct {
	options            *tunnelClientOptions
	proxy              *socksproxy.ProxyServer
	tunnelCtx          context.Context
	tunnelCtxCancel    context.CancelFunc
	insecureSkipVerify bool
	uuid               uuid.UUID
	authToken          string
	pcapPath           string
	rootCAs            *x509.CertPool

	hConn     *http3.ClientConn
	conn      *connectip.Conn
	tun       *netstack.TunDevice
	netstack  *network.NetstackNetwork
	closeOnce sync.Once
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

	client := &TunnelClient{
		options:            options,
		uuid:               options.uuid,
		authToken:          options.authToken,
		pcapPath:           options.pcapPath,
		rootCAs:            options.rootCAs,
		insecureSkipVerify: options.insecureSkipVerify,
	}

	return client, nil
}

// Start establishes a connection to the server and begins forwarding traffic.
func (c *TunnelClient) Start(ctx context.Context) error {
	c.tunnelCtx, c.tunnelCtxCancel = context.WithCancel(ctx)

	tlsConfig := &tls.Config{
		ServerName:         "proxy",
		NextProtos:         []string{http3.NextProtoH3},
		RootCAs:            c.rootCAs,
		InsecureSkipVerify: c.insecureSkipVerify,
	}

	if addr, _, err := net.SplitHostPort(c.options.serverAddr); err == nil && net.ParseIP(addr) == nil {
		tlsConfig.ServerName = addr
	}

	qConn, err := quic.DialAddr(
		ctx,
		c.options.serverAddr,
		tlsConfig,
		&quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: 1350,
			KeepAlivePeriod:   5 * time.Second,
			MaxIdleTimeout:    5 * time.Minute,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to dial QUIC connection: %w", err)
	}

	tr := &http3.Transport{EnableDatagrams: true}
	c.hConn = tr.NewClientConn(qConn)

	template := uritemplate.MustNew(fmt.Sprintf("https://proxy/connect/%s?token=%s", c.uuid, c.authToken))

	var rsp *http.Response
	c.conn, rsp, err = connectip.Dial(ctx, c.hConn, template)
	if err != nil {
		return fmt.Errorf("failed to dial connect-ip connection: %w", err)
	}
	if rsp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", rsp.StatusCode)
	}

	slog.Info("Connected to server", slog.String("addr", c.options.serverAddr))

	localPrefixes, err := c.conn.LocalPrefixes(ctx)
	if err != nil {
		return fmt.Errorf("failed to get local IP addresses: %w", err)
	}
	if len(localPrefixes) == 0 {
		return errors.New("no local IP addresses available")
	}

	filteredLocalPrefixes := make([]netip.Prefix, 0, len(localPrefixes))
	for _, prefix := range localPrefixes {
		if !prefix.Addr().Is6() {
			slog.Warn("Skipping non-IPv6 address", slog.String("address", prefix.Addr().String()))
			continue
		}
		slog.Info("Adding IPv6 address", slog.String("prefix", prefix.String()))
		filteredLocalPrefixes = append(filteredLocalPrefixes, prefix)
	}

	resolveConf := &network.ResolveConfig{
		Nameservers:   rsp.Header.Values("X-Apoxy-Nameservers"),
		SearchDomains: rsp.Header.Values("X-Apoxy-DNS-SearchDomains"),
	}

	if opts := rsp.Header.Values("X-Apoxy-DNS-Options"); len(opts) > 0 {
		for _, opt := range opts {
			if strings.HasPrefix(opt, "ndots:") {
				var ndots int
				if n, err := fmt.Sscanf(opt[6:], "%d", &ndots); err != nil || n != 1 {
					ndots = 1
				}
				resolveConf.NDots = &ndots
			}
		}
	}

	slog.Info("Using DNS configuration",
		slog.Any("nameservers", resolveConf.Nameservers),
		slog.Any("searchDomains", resolveConf.SearchDomains),
		slog.Any("nDots", resolveConf.NDots))

	c.tun, err = netstack.NewTunDevice(filteredLocalPrefixes, nil, c.pcapPath)
	if err != nil {
		return fmt.Errorf("failed to create virtual TUN device: %w", err)
	}

	c.netstack = c.tun.Network(resolveConf)

	go connection.Splice(c.tun, c.conn)

	_, socksListenPortStr, err := net.SplitHostPort(c.options.socksListenAddr)
	if err != nil {
		return fmt.Errorf("failed to parse SOCKS listen address: %w", err)
	}

	socksListenPort, err := strconv.Atoi(socksListenPortStr)
	if err != nil {
		return fmt.Errorf("failed to parse SOCKS listen port: %w", err)
	}

	slog.Info("Forwarding all inbound traffic to loopback interface")

	if err := c.tun.ForwardTo(c.tunnelCtx, network.Filtered(&network.FilteredNetworkConfig{
		DeniedPorts: []uint16{uint16(socksListenPort)},
		Upstream:    network.Loopback(),
	})); err != nil {
		return fmt.Errorf("failed to forward to loopback: %w", err)
	}

	slog.Info("Starting SOCKS5 proxy", slog.String("listenAddr", c.options.socksListenAddr))

	go func() {
		c.proxy = socksproxy.NewServer(c.options.socksListenAddr, c.netstack, network.Host())

		if err := c.proxy.ListenAndServe(c.tunnelCtx); err != nil {
			slog.Error("SOCKS proxy error", slog.String("error", err.Error()))
		}
	}()

	return nil
}

// Stop closes the tunnel client and stops forwarding traffic.
func (c *TunnelClient) Stop() error {
	// Stop any background tasks (and the SOCKS5 proxy).
	if c.tunnelCtxCancel != nil {
		c.tunnelCtxCancel()
	}
	return c.Close()
}

func (c *TunnelClient) Close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		if c.conn != nil {
			if err := c.conn.Close(); err != nil {
				closeErr = fmt.Errorf("failed to close connect-ip connection: %w", err)
			}
		}
		if c.tun != nil {
			if err := c.tun.Close(); err != nil {
				if closeErr != nil {
					closeErr = fmt.Errorf("%v; also failed to close TUN device: %w", closeErr, err)
				} else {
					closeErr = fmt.Errorf("failed to close TUN device: %w", err)
				}
			}
		}
		if c.hConn != nil {
			if err := c.hConn.CloseWithError(ApplicationCodeOK, ""); err != nil {
				if closeErr != nil {
					closeErr = fmt.Errorf("%v; also failed to close HTTP/3 connection: %w", closeErr, err)
				} else {
					closeErr = fmt.Errorf("failed to close HTTP/3 connection: %w", err)
				}
			}
		}
	})
	return closeErr
}

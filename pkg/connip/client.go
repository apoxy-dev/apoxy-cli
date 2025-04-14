package connip

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
)

const (
	ApplicationCodeOK quic.ApplicationErrorCode = 0x0
)

var _ TunnelTransport = (*ClientTransport)(nil)

type ClientConfig struct {
	// The UUID identifying the client.
	UUID uuid.UUID
	// The authentication token for the client.
	AuthToken string
	// The optional path to a packet capture file.
	PcapPath string
	// Optional root CA certificates for TLS verification.
	RootCAs *x509.CertPool
	// Optional flag to skip TLS verification.
	InsecureSkipVerify bool
}

type ClientTransport struct {
	*network.NetstackNetwork
	insecureSkipVerify bool
	uuid               uuid.UUID
	authToken          string
	pcapPath           string
	rootCAs            *x509.CertPool

	hConn     *http3.ClientConn
	conn      *connectip.Conn
	tun       *netstack.TunDevice
	closeOnce sync.Once
}

func NewClientTransport(conf *ClientConfig) *ClientTransport {
	return &ClientTransport{
		insecureSkipVerify: conf.InsecureSkipVerify,
		uuid:               conf.UUID,
		authToken:          conf.AuthToken,
		pcapPath:           conf.PcapPath,
		rootCAs:            conf.RootCAs,
	}
}

func (t *ClientTransport) Connect(ctx context.Context, serverAddr string) error {
	tlsConfig := &tls.Config{
		ServerName:         "proxy",
		NextProtos:         []string{http3.NextProtoH3},
		RootCAs:            t.rootCAs,
		InsecureSkipVerify: t.insecureSkipVerify,
	}

	// Use the proxy address as the server name if it is a domain.
	if addr, _, err := net.SplitHostPort(serverAddr); err == nil && net.ParseIP(addr) == nil {
		tlsConfig.ServerName = addr
	}

	qConn, err := quic.DialAddr(
		ctx,
		serverAddr,
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
	t.hConn = tr.NewClientConn(qConn)

	template := uritemplate.MustNew(fmt.Sprintf("https://proxy/connect/%s?token=%s", t.uuid, t.authToken))

	var rsp *http.Response
	t.conn, rsp, err = connectip.Dial(ctx, t.hConn, template)
	if err != nil {
		return fmt.Errorf("failed to dial connect-ip connection: %w", err)
	}
	if rsp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", rsp.StatusCode)
	}

	slog.Info("Connected to server", slog.String("addr", serverAddr))

	localPrefixes, err := t.conn.LocalPrefixes(ctx)
	if err != nil {
		return fmt.Errorf("failed to get local IP addresses: %w", err)
	}
	if len(localPrefixes) == 0 {
		return errors.New("no local IP addresses available")
	}

	// Filter out non-IPv6 addresses.
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

	// Parse DNS options from response headers.
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

	t.tun, err = netstack.NewTunDevice(filteredLocalPrefixes, nil, t.pcapPath)
	if err != nil {
		return fmt.Errorf("failed to create virtual TUN device: %w", err)
	}

	t.NetstackNetwork = t.tun.Network(resolveConf)

	// TODO (dpeckett): how to bubble up errors from this?
	go Splice(t.tun, t.conn)

	return nil
}

func (t *ClientTransport) Close() error {
	var closeErr error

	t.closeOnce.Do(func() {
		if t.conn != nil {
			if err := t.conn.Close(); err != nil {
				closeErr = fmt.Errorf("failed to close connect-ip connection: %w", err)
			}
		}

		if t.tun != nil {
			if err := t.tun.Close(); err != nil {
				// combine errors if both fail
				if closeErr != nil {
					closeErr = fmt.Errorf("%v; also failed to close TUN device: %w", closeErr, err)
				} else {
					closeErr = fmt.Errorf("failed to close TUN device: %w", err)
				}
			}
		}

		if t.hConn != nil {
			if err := t.hConn.CloseWithError(ApplicationCodeOK, ""); err != nil {
				// combine errors if both fail
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

// FowardTo forwards all inbound traffic to the upstream network.
func (t *ClientTransport) FowardTo(ctx context.Context, upstream network.Network) error {
	return t.tun.ForwardTo(ctx, upstream)
}

// LocalAddresses returns the local addresses assigned to the client.
func (t *ClientTransport) LocalAddresses() ([]netip.Prefix, error) {
	return t.tun.LocalAddresses()
}

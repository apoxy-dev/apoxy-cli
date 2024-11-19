package socksproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/bufferpool"

	"github.com/apoxy-dev/apoxy-cli/pkg/network"
)

// ProxyServer is a SOCKS5 proxy server.
type ProxyServer struct {
	Addr   string
	server *socks5.Server
}

// NewServer creates a new SOCKS5 proxy server.
func NewServer(addr string, upstream network.Network) *ProxyServer {
	options := []socks5.Option{
		socks5.WithDial(upstream.DialContext),
		socks5.WithResolver(&resolver{net: upstream}),
		socks5.WithBufferPool(bufferpool.NewPool(256 * 1024)),
		// No auth as we'll be binding exclusively to a local interface.
		socks5.WithAuthMethods([]socks5.Authenticator{socks5.NoAuthAuthenticator{}}),
	}

	return &ProxyServer{
		Addr:   addr,
		server: socks5.NewServer(options...),
	}
}

func (s *ProxyServer) ListenAndServe(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	go func() {
		<-ctx.Done()

		if err := lis.Close(); err != nil {
			slog.Warn("failed to close listener", slog.Any("error", err))
		}
	}()

	if err := s.server.Serve(lis); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("failed to serve: %w", err)
	}

	return nil
}

type resolver struct {
	net network.Network
}

func (r *resolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addrs, err := r.net.LookupContextHost(ctx, name)
	if err != nil {
		return ctx, nil, err
	}

	if len(addrs) == 0 {
		return ctx, nil, fmt.Errorf("no addresses found for %s", name)
	}

	ip := net.ParseIP(addrs[0])
	if ip == nil {
		return ctx, nil, fmt.Errorf("failed to parse IP address %s", addrs[0])
	}

	return ctx, ip, nil
}

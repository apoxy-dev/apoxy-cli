// Package tunnel implements TCP/UDP forwarding over WireGuard.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/google/uuid"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/utils/ptr"

	"github.com/apoxy-dev/apoxy-cli/pkg/socksproxy"
	"github.com/apoxy-dev/apoxy-cli/pkg/utils"
	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard"
)

type Tunnel struct {
	wgNet    *wireguard.WireGuardNetwork
	proxySrv *socksproxy.ProxyServer
}

// CreateTunnel creates a new user-space WireGuard tunnel.
func CreateTunnel(
	ctx context.Context,
	projectID uuid.UUID,
	endpoint string,
	socksPort uint16,
	verbose bool,
) (*Tunnel, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("could not generate private key: %w", err)
	}

	listenPort, err := utils.UnusedUDP4Port()
	if err != nil {
		return nil, fmt.Errorf("could not pick unused UDP port: %w", err)
	}

	ip6to4 := NewApoxy4To6Prefix(projectID, endpoint)

	wgNet, err := wireguard.Network(&wireguard.DeviceConfig{
		PrivateKey: ptr.To(privateKey.String()),
		ListenPort: ptr.To(listenPort),
		Verbose:    ptr.To(verbose),
		Address:    []string{ip6to4.String()},
		STUNServers: []string{
			"stun.l.google.com:19302",
			"stun1.l.google.com:19302",
			"stun2.l.google.com:19302",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("could not create WireGuard network: %w", err)
	}

	// Direct all inbound traffic to the loopback interface.
	// TODO (dpeckett): Add support for arbitrary routing.
	if err := wgNet.FowardToLoopback(ctx); err != nil {
		return nil, fmt.Errorf("could not forward traffic to loopback interface: %w", err)
	}

	// Create a SOCKS5 proxy server for outbound traffic.
	proxySrv := socksproxy.NewServer(net.JoinHostPort("localhost", fmt.Sprint(socksPort)), wgNet)

	// Start the proxy server (will be closed when the wireguard network is torn down).
	go func() {
		if err := proxySrv.ListenAndServe(ctx); err != nil && !(errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)) {
			slog.Error("failed to start SOCKS5 proxy server", slog.Any("error", err))
		}
	}()

	return &Tunnel{
		wgNet:    wgNet,
		proxySrv: proxySrv,
	}, nil
}

func (t *Tunnel) AddPeer(peerConf *wireguard.PeerConfig) error {
	return t.wgNet.AddPeer(peerConf)
}

func (t *Tunnel) RemovePeer(publicKey string) error {
	return t.wgNet.RemovePeer(publicKey)
}

func (t *Tunnel) PublicKey() string {
	return t.wgNet.PublicKey()
}

func (t *Tunnel) ExternalAddress() netip.AddrPort {
	return t.wgNet.Endpoint()
}

func (t *Tunnel) InternalAddress() netip.Prefix {
	return t.wgNet.LocalAddresses()[0]
}

func (t *Tunnel) ProxyAddress() string {
	return t.proxySrv.Addr
}

func (t *Tunnel) Close() {
	t.wgNet.Close()
}

// Package tunnel implements TCP/UDP forwarding over WireGuard.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/utils/ptr"

	"github.com/apoxy-dev/apoxy-cli/pkg/socksproxy"
	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard"
	"github.com/dpeckett/network"
)

var _ Tunnel = (*userspaceTunnel)(nil)

type userspaceTunnel struct {
	wgNet    *wireguard.WireGuardNetwork
	proxySrv *socksproxy.ProxyServer
}

// CreateUserspaceTunnel creates a new user-space WireGuard tunnel.
func CreateUserspaceTunnel(
	ctx context.Context,
	addr netip.Addr,
	socksPort uint16,
	packetCapturePath string,
	verbose bool,
) (*userspaceTunnel, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("could not generate private key: %w", err)
	}

	wgNet, err := wireguard.Network(&wireguard.DeviceConfig{
		PrivateKey:        ptr.To(privateKey.String()),
		Verbose:           ptr.To(verbose),
		PacketCapturePath: packetCapturePath,
		Address:           []string{addr.String()},
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
	proxySrv := socksproxy.NewServer(net.JoinHostPort("localhost", fmt.Sprint(socksPort)), wgNet, network.Host())

	// Start the proxy server (will be closed when the wireguard network is torn down).
	go func() {
		if err := proxySrv.ListenAndServe(ctx); err != nil && !(errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)) {
			slog.Error("failed to start SOCKS5 proxy server", slog.Any("error", err))
		}
	}()

	return &userspaceTunnel{
		wgNet:    wgNet,
		proxySrv: proxySrv,
	}, nil
}

func (t *userspaceTunnel) Close() error {
	t.wgNet.Close()
	return nil
}

func (t *userspaceTunnel) Peers() ([]wireguard.PeerConfig, error) {
	return t.wgNet.Peers()
}

func (t *userspaceTunnel) AddPeer(peerConf *wireguard.PeerConfig) error {
	return t.wgNet.AddPeer(peerConf)
}

func (t *userspaceTunnel) RemovePeer(publicKey string) error {
	return t.wgNet.RemovePeer(publicKey)
}

func (t *userspaceTunnel) PublicKey() string {
	return t.wgNet.PublicKey()
}

func (t *userspaceTunnel) InternalAddress() netip.Prefix {
	return t.wgNet.LocalAddresses()[0]
}

func (t *userspaceTunnel) ListenPort() (uint16, error) {
	return t.wgNet.ListenPort()
}

// Package tunnel implements TCP/UDP forwarding over WireGuard.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard"
	"github.com/google/uuid"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/utils/ptr"
)

type Tunnel struct {
	wgNet *wireguard.WireGuardNetwork
}

// CreateTunnel creates a new WireGuard device (userspace).
func CreateTunnel(
	ctx context.Context,
	projectID uuid.UUID,
	endpoint string,
	verbose bool,
) (*Tunnel, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("could not generate private key: %v", err)
	}

	listenPort, err := pickUnusedUDP4Port()
	if err != nil {
		return nil, fmt.Errorf("could not pick unused UDP port: %v", err)
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
		return nil, fmt.Errorf("could not create WireGuard network: %v", err)
	}

	// Direct all inbound traffic to the loopback interface.
	// TODO (dpeckett): Add support for arbitrary routing.
	if err := wgNet.FowardToLoopback(ctx); err != nil {
		return nil, fmt.Errorf("could not forward traffic to loopback interface: %v", err)
	}

	return &Tunnel{
		wgNet: wgNet,
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

func (t *Tunnel) Close() {
	t.wgNet.Close()
}

func pickUnusedUDP4Port() (uint16, error) {
	for i := 0; i < 10; i++ {
		addr, err := net.ResolveUDPAddr("udp4", "localhost:0")
		if err != nil {
			return 0, err
		}
		l, err := net.ListenUDP("udp4", addr)
		if err != nil {
			return 0, err
		}
		defer l.Close()
		return uint16(l.LocalAddr().(*net.UDPAddr).Port), nil
	}
	return 0, errors.New("could not find unused UDP port")
}

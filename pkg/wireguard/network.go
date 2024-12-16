package wireguard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/utils/ptr"

	"github.com/apoxy-dev/apoxy-cli/pkg/network"
	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard/netstack"
	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard/uapi"
)

var _ network.Network = (*WireGuardNetwork)(nil)

// WireGuardNetwork is a user-space network implementation that uses WireGuard.
type WireGuardNetwork struct {
	dev        *device.Device
	tnet       *netstack.NetTun
	privateKey wgtypes.Key
	endpoint   netip.AddrPort
}

// Network returns a new WireGuardNetwork.
func Network(conf *DeviceConfig) (*WireGuardNetwork, error) {
	if conf.PrivateKey == nil {
		return nil, errors.New("private key is required")
	}

	privateKey, err := wgtypes.ParseKey(*conf.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	localAddresses, err := parseAddressList(conf.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse local addresses: %w", err)
	}

	dnsServers, err := parseAddressList(conf.DNS)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DNS servers: %w", err)
	}

	tun, tnet, err := netstack.CreateNetTUN(localAddresses, dnsServers, conf.MTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create netstack device: %w", err)
	}

	bind := conn.NewDefaultBind()

	var endpoint netip.AddrPort
	if len(conf.STUNServers) > 0 {
		endpoint, err = TryStun(context.Background(), bind, *conf.ListenPort, conf.STUNServers...)
		if err != nil {
			return nil, err
		}
	}

	dev := device.NewDevice(tun, bind, &device.Logger{
		Verbosef: func(format string, args ...any) {
			// wireguard-go logs a ton of stuff at the verbose level.
			if conf.Verbose != nil && *conf.Verbose {
				slog.Debug(fmt.Sprintf(format, args...))
			}
		},
		Errorf: func(format string, args ...any) {
			slog.Error(fmt.Sprintf(format, args...))
		},
	})

	uapiConf, err := uapi.Marshal(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal device config: %w", err)
	}

	if err := dev.IpcSet(uapiConf); err != nil {
		return nil, err
	}

	if err := dev.Up(); err != nil {
		return nil, err
	}

	return &WireGuardNetwork{
		dev:        dev,
		tnet:       tnet,
		privateKey: privateKey,
		endpoint:   endpoint,
	}, nil
}

func (n *WireGuardNetwork) Close() {
	n.dev.Close()
}

// PublicKey returns the public key for this peer on the WireGuard network.
func (n *WireGuardNetwork) PublicKey() string {
	return n.privateKey.PublicKey().String()
}

// LocalAddresses returns the list of local addresses assigned to the WireGuard network.
func (n *WireGuardNetwork) LocalAddresses() []netip.Prefix {
	return n.tnet.LocalAddresses()
}

// Endpoint returns the external endpoint of the WireGuard network.
func (n *WireGuardNetwork) Endpoint() netip.AddrPort {
	return n.endpoint
}

// Peers returns the list of public keys for all peers on the WireGuard network.
func (n *WireGuardNetwork) Peers() ([]PeerConfig, error) {
	var uapiConf strings.Builder
	if err := n.dev.IpcGetOperation(&uapiConf); err != nil {
		return nil, fmt.Errorf("failed to get device config: %w", err)
	}

	entries := strings.Split(uapiConf.String(), "public_key=")

	// The first entry is the device config (which we don't care about).
	var peers []PeerConfig
	for _, entry := range entries[1:] {
		// Subsequent entries are peer configs.
		entry = "public_key=" + entry

		var peerConf PeerConfig
		if err := uapi.Unmarshal(entry, &peerConf); err != nil {
			return nil, fmt.Errorf("failed to unmarshal peer config: %w", err)
		}

		peers = append(peers, peerConf)
	}

	return peers, nil
}

// AddPeer adds, or updates, a peer to the WireGuard network.
func (n *WireGuardNetwork) AddPeer(peerConf *PeerConfig) error {
	if peerConf.Endpoint != nil {
		host, port, err := net.SplitHostPort(*peerConf.Endpoint)
		if err != nil {
			return fmt.Errorf("failed to parse peer endpoint: %w", err)
		}

		if _, err := netip.ParseAddr(host); err != nil {
			// If the endpoint is a hostname, resolve it.
			ips, err := net.LookupHost(host)
			if err != nil {
				return fmt.Errorf("failed to resolve endpoint: %w", err)
			}

			// TODO: Use a proper IP address selection algorithm.
			peerConf.Endpoint = ptr.To(net.JoinHostPort(ips[0], port))
		}
	}

	uapiPeerConf, err := uapi.Marshal(peerConf)
	if err != nil {
		return fmt.Errorf("failed to marshal peer config: %w", err)
	}

	if err := n.dev.IpcSet(uapiPeerConf); err != nil {
		return fmt.Errorf("failed to add peer: %w", err)
	}

	return nil
}

// RemovePeer removes a peer from the WireGuard network.
func (n *WireGuardNetwork) RemovePeer(publicKey string) error {
	peerConf := &PeerConfig{
		PublicKey: ptr.To(publicKey),
		Remove:    ptr.To(true),
	}

	uapiPeerConf, err := uapi.Marshal(peerConf)
	if err != nil {
		return fmt.Errorf("failed to marshal peer config: %w", err)
	}

	if err := n.dev.IpcSet(uapiPeerConf); err != nil {
		return fmt.Errorf("failed to remove peer: %w", err)
	}

	return nil
}

func (n *WireGuardNetwork) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	slog.Debug("Dialing", slog.String("network", network), slog.String("addr", addr))
	return n.tnet.DialContext(ctx, network, addr)
}

func (n *WireGuardNetwork) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	return n.tnet.LookupContextHost(ctx, host)
}

// FowardToLoopback forwards all inbound traffic to the loopback interface.
func (n *WireGuardNetwork) FowardToLoopback(ctx context.Context) error {
	if err := n.tnet.EnableForwarding(netstack.TCPForwarder(ctx, &netstack.TCPForwarderConfig{
		AllowedDestinations: n.tnet.LocalAddresses(),
		Upstream:            network.Loopback(),
	}), false); err != nil {
		return fmt.Errorf("failed to enable forwarding: %w", err)
	}

	return nil
}

func parseAddressList(addrs []string) ([]netip.Addr, error) {
	var parsed []netip.Addr
	for _, addr := range addrs {
		// Is it a CIDR?
		if prefix, err := netip.ParsePrefix(addr); err == nil {
			parsed = append(parsed, prefix.Addr())
			continue
		}

		parsedAddr, err := netip.ParseAddr(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse address: %w", err)
		}

		parsed = append(parsed, parsedAddr)
	}

	return parsed, nil
}

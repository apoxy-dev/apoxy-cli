package wireguard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/dpeckett/network"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"k8s.io/utils/ptr"

	"github.com/apoxy-dev/apoxy-cli/pkg/netstack"
	"github.com/apoxy-dev/apoxy-cli/pkg/utils"
	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard/uapi"
)

var _ TunnelTransport = (*UserspaceTransport)(nil)

// UserspaceTransport is a user-space network implementation that uses WireGuard.
type UserspaceTransport struct {
	*network.NetstackNetwork
	tun        *tunDevice
	dev        *device.Device
	privateKey wgtypes.Key
}

// NewUserspaceTransport returns a new userspace wireguard network.
func NewUserspaceTransport(conf *DeviceConfig) (*UserspaceTransport, error) {
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

	tun, err := newTunDevice(localAddresses, conf.MTU, conf.PacketCapturePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create netstack device: %w", err)
	}

	bind := conn.NewStdNetBind()

	if conf.ListenPort == nil {
		listenPort, err := utils.UnusedUDP4Port()
		if err != nil {
			return nil, fmt.Errorf("could not pick unused UDP port: %w", err)
		}

		conf.ListenPort = ptr.To(listenPort)
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

	// TODO: allow configuring ndots/search etc.
	resolveConf := &network.ResolveConfig{
		Nameservers: conf.DNS,
	}

	return &UserspaceTransport{
		NetstackNetwork: network.Netstack(tun.stack, tun.nicID, resolveConf),
		tun:             tun,
		dev:             dev,
		privateKey:      privateKey,
	}, nil
}

func (t *UserspaceTransport) Close() error {
	t.dev.Close() // Closes tun device internally.
	return nil
}

// PublicKey returns the public key for this peer on the WireGuard network.
func (t *UserspaceTransport) PublicKey() string {
	return t.privateKey.PublicKey().String()
}

// ListenPort returns the local listen port of this end of the tunnel.
func (t *UserspaceTransport) ListenPort() (uint16, error) {
	var uapiConf strings.Builder
	if err := t.dev.IpcGetOperation(&uapiConf); err != nil {
		return 0, fmt.Errorf("failed to get device config: %w", err)
	}

	entries := strings.Split(uapiConf.String(), "public_key=")
	if len(entries) == 0 {
		return 0, errors.New("no device config found")
	}

	var conf DeviceConfig
	if err := uapi.Unmarshal(entries[0], &conf); err != nil {
		return 0, fmt.Errorf("failed to unmarshal device config: %w", err)
	}

	if conf.ListenPort == nil {
		return 0, errors.New("no listen port found")
	}

	return *conf.ListenPort, nil
}

// LocalAddresses returns the list of local addresses assigned to the WireGuard network.
func (t *UserspaceTransport) LocalAddresses() ([]netip.Prefix, error) {
	nic := t.tun.stack.NICInfo()[t.tun.nicID]

	var addrs []netip.Prefix
	for _, assignedAddr := range nic.ProtocolAddresses {
		addrs = append(addrs, netip.PrefixFrom(
			addrFromNetstackIP(assignedAddr.AddressWithPrefix.Address),
			assignedAddr.AddressWithPrefix.PrefixLen,
		))
	}

	return addrs, nil
}

// FowardToLoopback forwards all inbound traffic to the loopback interface.
func (t *UserspaceTransport) FowardToLoopback(ctx context.Context) error {
	// Allow outgoing packets to have a source address different from the address
	// assigned to the NIC.
	if tcpipErr := t.tun.stack.SetSpoofing(t.tun.nicID, true); tcpipErr != nil {
		return fmt.Errorf("failed to enable spoofing: %v", tcpipErr)
	}

	// Allow incoming packets to have a destination address different from the
	// address assigned to the NIC.
	if tcpipErr := t.tun.stack.SetPromiscuousMode(t.tun.nicID, true); tcpipErr != nil {
		return fmt.Errorf("failed to enable promiscuous mode: %v", tcpipErr)
	}

	tcpForwarder := netstack.TCPForwarder(ctx, t.tun.stack, network.Loopback())

	t.tun.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder)

	return nil
}

// Peers returns the list of public keys for all peers on the WireGuard network.
func (n *UserspaceTransport) Peers() ([]PeerConfig, error) {
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
func (t *UserspaceTransport) AddPeer(peerConf *PeerConfig) error {
	if peerConf.Endpoint != nil {
		// If it's an address, resolve it. If it's a name pass it through unmodified.
		host, port, err := net.SplitHostPort(*peerConf.Endpoint)
		if err == nil {
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
	}

	// Don't set the persistent keep-alive interval immediately.
	var persistentKeepaliveIntervalSec *uint16
	if peerConf.PersistentKeepaliveIntervalSec != nil {
		persistentKeepaliveIntervalSec = ptr.To(*peerConf.PersistentKeepaliveIntervalSec)
	}
	peerConf.PersistentKeepaliveIntervalSec = nil

	uapiPeerConf, err := uapi.Marshal(peerConf)
	if err != nil {
		return fmt.Errorf("failed to marshal peer config: %w", err)
	}

	if err := t.dev.IpcSet(uapiPeerConf); err != nil {
		return fmt.Errorf("failed to add peer: %w", err)
	}

	// Workarround a mysterious race condition in wireguard-go where immediately
	// setting a persistent keep-alive interval after adding a peer will cause
	// handshake failures.
	if persistentKeepaliveIntervalSec != nil {
		peerConf.PersistentKeepaliveIntervalSec = persistentKeepaliveIntervalSec

		go func() {
			time.Sleep(time.Second)

			uapiPeerConf, err := uapi.Marshal(&PeerConfig{
				PublicKey:                      peerConf.PublicKey,
				PersistentKeepaliveIntervalSec: peerConf.PersistentKeepaliveIntervalSec,
				UpdateOnly:                     ptr.To(true),
			})
			if err != nil {
				slog.Warn("failed to marshal peer config", slog.Any("error", err))
			}

			if err := t.dev.IpcSet(uapiPeerConf); err != nil {
				slog.Warn("failed to set persistent keep-alive interval", slog.Any("error", err))
			}
		}()
	}

	return nil
}

// RemovePeer removes a peer from the WireGuard network.
func (t *UserspaceTransport) RemovePeer(publicKey string) error {
	peerConf := &PeerConfig{
		PublicKey: ptr.To(publicKey),
		Remove:    ptr.To(true),
	}

	uapiPeerConf, err := uapi.Marshal(peerConf)
	if err != nil {
		return fmt.Errorf("failed to marshal peer config: %w", err)
	}

	if err := t.dev.IpcSet(uapiPeerConf); err != nil {
		return fmt.Errorf("failed to remove peer: %w", err)
	}

	return nil
}

func parseAddressList(addrs []string) ([]netip.Prefix, error) {
	var parsed []netip.Prefix
	for _, addr := range addrs {
		// Is it a CIDR?
		if prefix, err := netip.ParsePrefix(addr); err == nil {
			parsed = append(parsed, prefix)
			continue
		}

		parsedAddr, err := netip.ParseAddr(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse address: %w", err)
		}

		parsed = append(parsed, netip.PrefixFrom(parsedAddr, parsedAddr.BitLen()))
	}

	return parsed, nil
}

func addrFromNetstackIP(ip tcpip.Address) netip.Addr {
	switch ip.Len() {
	case 4:
		ip := ip.As4()
		return netip.AddrFrom4([4]byte{ip[0], ip[1], ip[2], ip[3]})
	case 16:
		ip := ip.As16()
		return netip.AddrFrom16(ip).Unmap()
	}
	return netip.Addr{}
}

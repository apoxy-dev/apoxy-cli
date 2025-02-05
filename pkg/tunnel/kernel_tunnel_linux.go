//go:build linux
// +build linux

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/utils/ptr"

	"github.com/apoxy-dev/apoxy-cli/pkg/utils"
	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard"
	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard/netstack"
)

var _ Tunnel = (*kernelTunnel)(nil)

type kernelTunnel struct {
	privateKey      wgtypes.Key
	ifaceName       string
	listenPort      uint16
	externalAddress netip.AddrPort
	wgClient        *wgctrl.Client
}

// CreateKernelTunnel creates a new kernel tunnel interface (WireGuard).
func CreateKernelTunnel(
	ctx context.Context,
	addr netip.Prefix,
	stunServers []string,
) (*kernelTunnel, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("could not generate private key: %w", err)
	}

	listenPort, err := utils.UnusedUDP4Port()
	if err != nil {
		return nil, fmt.Errorf("could not pick unused UDP port: %w", err)
	}

	slog.Debug("Listening for wireguard traffic", slog.Int("port", int(listenPort)))

	bind := conn.NewDefaultBind()
	externalAddress, err := wireguard.TryStun(context.Background(), bind, listenPort, stunServers...)
	_ = bind.Close()
	if err != nil {
		return nil, err
	}

	// Find the next available network interface index, e.g., wg0, wg1, etc.
	ifaceName, err := findNextAvailableInterface()
	if err != nil {
		return nil, fmt.Errorf("could not find next available interface: %w", err)
	}

	// Create the kernel tunnel interface (WireGuard).
	link := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{
			Name: ifaceName,
			MTU:  netstack.DefaultMTU,
		},
		LinkType: "wireguard",
	}

	if err := netlink.LinkAdd(link); err != nil {
		return nil, fmt.Errorf("could not create WireGuard interface: %w", err)
	}

	// Set the address of the kernel tunnel interface.
	naddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   addr.Addr().AsSlice(),
			Mask: net.CIDRMask(addr.Bits(), len(addr.Addr().AsSlice())*8),
		},
	}
	if err := netlink.AddrAdd(link, naddr); err != nil {
		return nil, fmt.Errorf("could not assign address to interface %s: %w", ifaceName, err)
	}

	// Bring the interface up.
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("could not bring interface %s up: %w", ifaceName, err)
	}

	// Initialize wgctrl client.
	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("could not initialize wgctrl client: %w", err)
	}

	// Configure the WireGuard device with the private key.
	wgConfig := wgtypes.Config{
		PrivateKey: &privateKey,
		ListenPort: ptr.To(int(listenPort)),
	}

	if err := wgClient.ConfigureDevice(ifaceName, wgConfig); err != nil {
		return nil, fmt.Errorf("could not configure WireGuard device: %w", err)
	}

	return &kernelTunnel{
		privateKey:      privateKey,
		ifaceName:       ifaceName,
		listenPort:      listenPort,
		externalAddress: externalAddress,
		wgClient:        wgClient,
	}, nil
}

func (t *kernelTunnel) Close() error {
	defer t.wgClient.Close()

	link, err := netlink.LinkByName(t.ifaceName)
	if err != nil {
		return fmt.Errorf("could not find interface %s: %w", t.ifaceName, err)
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("could not delete interface %s: %w", t.ifaceName, err)
	}

	return nil
}

func (t *kernelTunnel) Peers() ([]wireguard.PeerConfig, error) {
	device, err := t.wgClient.Device(t.ifaceName)
	if err != nil {
		return nil, fmt.Errorf("could not fetch WireGuard device info: %w", err)
	}

	peers := make([]wireguard.PeerConfig, len(device.Peers))
	for i, peer := range device.Peers {
		peerConf := wireguard.PeerConfig{
			PublicKey:                      ptr.To(peer.PublicKey.String()),
			PresharedKey:                   ptr.To(peer.PresharedKey.String()),
			Endpoint:                       ptr.To(peer.Endpoint.String()),
			AllowedIPs:                     make([]string, len(peer.AllowedIPs)),
			PersistentKeepaliveIntervalSec: ptr.To(uint16(peer.PersistentKeepaliveInterval / time.Second)),
		}

		for j, allowedIP := range peer.AllowedIPs {
			peerConf.AllowedIPs[j] = allowedIP.String()
		}

		peers[i] = peerConf
	}

	return peers, nil
}

func (t *kernelTunnel) AddPeer(peerConf *wireguard.PeerConfig) error {
	publicKey, err := wgtypes.ParseKey(*peerConf.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	peer := wgtypes.PeerConfig{
		PublicKey:  publicKey,
		AllowedIPs: convertAllowedIPs(peerConf.AllowedIPs),
	}

	if peerConf.Endpoint != nil {
		hostStr, portStr, err := net.SplitHostPort(*peerConf.Endpoint)
		if err != nil {
			return fmt.Errorf("failed to parse peer endpoint: %w", err)
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("invalid peer endpoint port: %w", err)
		}

		ip := net.ParseIP(hostStr)
		if ip == nil {
			// If the endpoint is a hostname, resolve it.
			ips, err := net.LookupHost(hostStr)
			if err != nil {
				return fmt.Errorf("failed to resolve endpoint: %w", err)
			}

			// TODO: Use a proper IP address selection algorithm.
			ip = net.ParseIP(ips[0])
		}

		peer.Endpoint = &net.UDPAddr{
			IP:   ip,
			Port: port,
		}
	}

	if peerConf.PersistentKeepaliveIntervalSec != nil {
		peer.PersistentKeepaliveInterval = ptr.To(time.Duration(*peerConf.PersistentKeepaliveIntervalSec) * time.Second)
	}

	if err := t.wgClient.ConfigureDevice(t.ifaceName, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}); err != nil {
		return fmt.Errorf("could not add peer to interface %s: %w", t.ifaceName, err)
	}

	// Add route to the peer's allowed IPs
	link, err := netlink.LinkByName(t.ifaceName)
	if err != nil {
		return fmt.Errorf("could not find interface %s: %w", t.ifaceName, err)
	}

	for _, allowedIP := range peerConf.AllowedIPs {
		prefix, err := netip.ParsePrefix(allowedIP)
		if err != nil {
			return fmt.Errorf("invalid allowed IP prefix: %w", err)
		}

		route := &netlink.Route{
			Dst: &net.IPNet{
				IP:   prefix.Addr().AsSlice(),
				Mask: net.CIDRMask(prefix.Bits(), len(prefix.Addr().AsSlice())*8),
			},
			LinkIndex: link.Attrs().Index,
		}

		if err := netlink.RouteAdd(route); err != nil {
			return fmt.Errorf("could not add route to %s: %w", allowedIP, err)
		}
	}

	return nil
}

func (t *kernelTunnel) RemovePeer(publicKey string) error {
	parsedKey, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	// Remove route to the peer's allowed IPs
	device, err := t.wgClient.Device(t.ifaceName)
	if err != nil {
		return fmt.Errorf("could not fetch WireGuard device info: %w", err)
	}

	var peerAllowedIPs []net.IPNet
	for _, p := range device.Peers {
		if p.PublicKey.String() == publicKey {
			peerAllowedIPs = p.AllowedIPs
			break
		}
	}

	link, err := netlink.LinkByName(t.ifaceName)
	if err != nil {
		return fmt.Errorf("could not find interface %s: %w", t.ifaceName, err)
	}

	for _, allowedIP := range peerAllowedIPs {
		route := &netlink.Route{
			Dst: &net.IPNet{
				IP:   allowedIP.IP,
				Mask: allowedIP.Mask,
			},
			LinkIndex: link.Attrs().Index,
		}

		if err := netlink.RouteDel(route); err != nil {
			return fmt.Errorf("could not remove route to %s: %w", allowedIP.String(), err)
		}
	}

	peer := wgtypes.PeerConfig{
		PublicKey: parsedKey,
		Remove:    true,
	}

	if err := t.wgClient.ConfigureDevice(t.ifaceName, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}); err != nil {
		return fmt.Errorf("could not remove peer from interface %s: %w", t.ifaceName, err)
	}

	return nil
}

func (t *kernelTunnel) PublicKey() string {
	return t.privateKey.PublicKey().String()
}

func (t *kernelTunnel) ExternalAddress() netip.AddrPort {
	return t.externalAddress
}

func (t *kernelTunnel) InternalAddress() netip.Prefix {
	link, err := netlink.LinkByName(t.ifaceName)
	if err != nil {
		return netip.Prefix{}
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return netip.Prefix{}
	}

	if len(addrs) == 0 {
		return netip.Prefix{}
	}

	prefix, _ := netip.ParsePrefix(addrs[0].IPNet.String())
	return prefix
}

func (t *kernelTunnel) ListenPort() uint16 {
	return t.listenPort
}

func (t *kernelTunnel) InterfaceName() string {
	return t.ifaceName
}

func findNextAvailableInterface() (string, error) {
	for i := 0; i < 255; i++ {
		name := fmt.Sprintf("wg%d", i)
		if _, err := netlink.LinkByName(name); errors.As(err, &netlink.LinkNotFoundError{}) {
			return name, nil
		}
	}
	return "", errors.New("no available interface names")
}

func convertAllowedIPs(allowedIPs []string) []net.IPNet {
	results := []net.IPNet{}
	for _, ip := range allowedIPs {
		if prefix, err := netip.ParsePrefix(ip); err == nil {
			results = append(results, net.IPNet{
				IP:   prefix.Addr().AsSlice(),
				Mask: net.CIDRMask(prefix.Bits(), len(prefix.Addr().AsSlice())*8),
			})

			continue
		}

		if addr, err := netip.ParseAddr(ip); err == nil {
			if addr.Is4() {
				results = append(results, net.IPNet{
					IP:   addr.AsSlice(),
					Mask: net.CIDRMask(32, 32),
				})
			} else {
				results = append(results, net.IPNet{
					IP:   addr.AsSlice(),
					Mask: net.CIDRMask(128, 128),
				})
			}
		}
	}

	return results
}

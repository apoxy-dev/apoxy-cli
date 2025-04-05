//go:build linux
// +build linux

package wireguard

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/dpeckett/network"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/utils/ptr"

	"github.com/apoxy-dev/apoxy-cli/pkg/netstack"
	"github.com/apoxy-dev/apoxy-cli/pkg/utils"
)

var _ TunnelTransport = (*KernelModeTransport)(nil)

type KernelModeTransport struct {
	*network.FilteredNetwork
	privateKey wgtypes.Key
	ifaceName  string
	listenPort uint16
	wgClient   *wgctrl.Client
}

// NewKernelModeTransport returns a new kernel mode wireguard network.
func NewKernelModeTransport(
	conf *DeviceConfig,
) (*KernelModeTransport, error) {
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

	if conf.ListenPort == nil {
		listenPort, err := utils.UnusedUDP4Port()
		if err != nil {
			return nil, fmt.Errorf("could not pick unused UDP port: %w", err)
		}

		conf.ListenPort = ptr.To(listenPort)
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
			MTU:  netstack.IPv6MinMTU,
		},
		LinkType: "wireguard",
	}

	if err := netlink.LinkAdd(link); err != nil {
		return nil, fmt.Errorf("could not create WireGuard interface: %w", err)
	}

	// Set the address of the kernel tunnel interface.
	for _, prefix := range localAddresses {
		nlAddr := &netlink.Addr{
			IPNet: &net.IPNet{
				IP:   prefix.Addr().AsSlice(),
				Mask: net.CIDRMask(prefix.Bits(), len(prefix.Addr().AsSlice())*8),
			},
			Label: ifaceName,
		}
		if err := netlink.AddrAdd(link, nlAddr); err != nil {
			return nil, fmt.Errorf("could not assign address to interface %s: %w", ifaceName, err)
		}
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
		ListenPort: ptr.To(int(*conf.ListenPort)),
	}

	if err := wgClient.ConfigureDevice(ifaceName, wgConfig); err != nil {
		return nil, fmt.Errorf("could not configure WireGuard device: %w", err)
	}

	return &KernelModeTransport{
		FilteredNetwork: network.Filtered(&network.FilteredNetworkConfig{
			AllowedDestinations: localAddresses,
			Upstream:            network.Host(),
		}),
		privateKey: privateKey,
		ifaceName:  ifaceName,
		listenPort: *conf.ListenPort,
		wgClient:   wgClient,
	}, nil
}

func (t *KernelModeTransport) Close() error {
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

func (t *KernelModeTransport) Peers() ([]PeerConfig, error) {
	device, err := t.wgClient.Device(t.ifaceName)
	if err != nil {
		return nil, fmt.Errorf("could not fetch WireGuard device info: %w", err)
	}

	peers := make([]PeerConfig, len(device.Peers))
	for i, peer := range device.Peers {
		peerConf := PeerConfig{
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

func (t *KernelModeTransport) AddPeer(peerConf *PeerConfig) error {
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

		t.FilteredNetwork.AddAllowedDestination(prefix)
	}

	return nil
}

func (t *KernelModeTransport) RemovePeer(publicKey string) error {
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

		addr, _ := netip.AddrFromSlice(allowedIP.IP)
		t.FilteredNetwork.RemoveAllowedDestination(netip.PrefixFrom(addr, len(allowedIP.Mask)*8))
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

func (t *KernelModeTransport) PublicKey() string {
	return t.privateKey.PublicKey().String()
}

func (t *KernelModeTransport) LocalAddresses() ([]netip.Prefix, error) {
	link, err := netlink.LinkByName(t.ifaceName)
	if err != nil {
		return nil, fmt.Errorf("could not find interface %s: %w", t.ifaceName, err)
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("failed to list addresses: %w", err)
	}

	var prefixes []netip.Prefix
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.IPNet.String())
		if err != nil {
			return nil, fmt.Errorf("failed to parse address: %w", err)
		}

		prefixes = append(prefixes, prefix)
	}

	return prefixes, nil
}

func (t *KernelModeTransport) ListenPort() (uint16, error) {
	return t.listenPort, nil
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

//go:build linux
// +build linux

package tunnel

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/utils/ptr"

	"github.com/apoxy-dev/apoxy-cli/pkg/utils"
	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard"
	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard/netstack"
	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard/uapi"
)

var _ Tunnel = (*kernelTunnel)(nil)

type kernelTunnel struct {
	dev        *device.Device
	privateKey wgtypes.Key
	ifaceName  string
	addr       netip.Prefix
}

// CreateKernelTunnel creates a new kernel tunnel interface (TUN).
func CreateKernelTunnel(
	addr netip.Prefix,
	bind conn.Bind,
	verbose bool,
) (*kernelTunnel, error) {
	// Find the next available network interface index, e.g., wg0, wg1, etc.
	ifaceName, err := findNextAvailableInterface()
	if err != nil {
		return nil, fmt.Errorf("could not find next available interface: %w", err)
	}

	tunDevice, err := tun.CreateTUN(ifaceName, netstack.DefaultMTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}

	var listenPort *uint16
	if bind == nil {
		bind = conn.NewStdNetBind()

		selectedListenPort, err := utils.UnusedUDP4Port()
		if err != nil {
			return nil, fmt.Errorf("could not pick unused UDP port: %w", err)
		}

		listenPort = ptr.To(selectedListenPort)
	}

	dev := device.NewDevice(tunDevice, bind, &device.Logger{
		Verbosef: func(format string, args ...any) {
			// wireguard-go logs a ton of stuff at the verbose level.
			if verbose {
				slog.Debug(fmt.Sprintf(format, args...))
			}
		},
		Errorf: func(format string, args ...any) {
			slog.Error(fmt.Sprintf(format, args...))
		},
	})

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("could not generate private key: %w", err)
	}

	uapiConf, err := uapi.Marshal(&wireguard.DeviceConfig{
		PrivateKey: ptr.To(privateKey.String()),
		ListenPort: listenPort,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal device config: %w", err)
	}

	if err := dev.IpcSet(uapiConf); err != nil {
		return nil, err
	}

	if err := dev.Up(); err != nil {
		return nil, err
	}

	// Find the tunnel interface by name.
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("could not find interface %s: %w", ifaceName, err)
	}

	// Bring the tunnel interface up.
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("could not bring interface %s up: %w", ifaceName, err)
	}

	// Set the address of the tunnel interface.
	naddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   addr.Addr().AsSlice(),
			Mask: net.CIDRMask(addr.Bits(), len(addr.Addr().AsSlice())*8),
		},
	}
	if err := netlink.AddrAdd(link, naddr); err != nil {
		return nil, fmt.Errorf("could not assign address to interface %s: %w", ifaceName, err)
	}

	return &kernelTunnel{
		dev:        dev,
		privateKey: privateKey,
		ifaceName:  ifaceName,
		addr:       addr,
	}, nil
}

func (t *kernelTunnel) Close() error {
	t.dev.Close()
	return nil
}

func (t *kernelTunnel) Peers() ([]wireguard.PeerConfig, error) {
	var uapiConf strings.Builder
	if err := t.dev.IpcGetOperation(&uapiConf); err != nil {
		return nil, fmt.Errorf("failed to get device config: %w", err)
	}

	entries := strings.Split(uapiConf.String(), "public_key=")

	// The first entry is the device config (which we don't care about).
	var peers []wireguard.PeerConfig
	for _, entry := range entries[1:] {
		// Subsequent entries are peer configs.
		entry = "public_key=" + entry

		var peerConf wireguard.PeerConfig
		if err := uapi.Unmarshal(entry, &peerConf); err != nil {
			return nil, fmt.Errorf("failed to unmarshal peer config: %w", err)
		}

		peers = append(peers, peerConf)
	}

	return peers, nil
}

func (t *kernelTunnel) AddPeer(peerConf *wireguard.PeerConfig) error {
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

			uapiPeerConf, err := uapi.Marshal(&wireguard.PeerConfig{
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
	// Remove route to the peer's allowed IPs
	peers, err := t.Peers()
	if err != nil {
		return err
	}

	var peerAllowedIPs []netip.Prefix
	for _, p := range peers {
		if *p.PublicKey == publicKey {
			for _, ipStr := range p.AllowedIPs {
				allowedIP, err := netip.ParsePrefix(ipStr)
				if err != nil {
					return fmt.Errorf("invalid allowed IP prefix: %w", err)
				}
				peerAllowedIPs = append(peerAllowedIPs, allowedIP)
			}
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
				IP:   allowedIP.Addr().AsSlice(),
				Mask: net.CIDRMask(allowedIP.Bits(), len(allowedIP.Addr().AsSlice())*8),
			},
			LinkIndex: link.Attrs().Index,
		}

		if err := netlink.RouteDel(route); err != nil {
			slog.Warn("Failed to remove route", slog.Any("error", err),
				slog.String("destination", route.Dst.String()))
		}
	}

	peerConf := &wireguard.PeerConfig{
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

func (t *kernelTunnel) PublicKey() string {
	return t.privateKey.PublicKey().String()
}

func (t *kernelTunnel) InternalAddress() netip.Prefix {
	return t.addr
}

func (t *kernelTunnel) ListenPort() (uint16, error) {
	var uapiConf strings.Builder
	if err := t.dev.IpcGetOperation(&uapiConf); err != nil {
		return 0, fmt.Errorf("failed to get device config: %w", err)
	}

	entries := strings.Split(uapiConf.String(), "public_key=")
	if len(entries) == 0 {
		return 0, errors.New("no device config found")
	}

	var conf wireguard.DeviceConfig
	if err := uapi.Unmarshal(entries[0], &conf); err != nil {
		return 0, fmt.Errorf("failed to unmarshal device config: %w", err)
	}

	if conf.ListenPort == nil {
		return 0, errors.New("no listen port found")
	}

	return *conf.ListenPort, nil
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

//go:build linux

package router

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/tun"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	utilexec "k8s.io/utils/exec"

	"github.com/apoxy-dev/apoxy-cli/pkg/connip"
	"github.com/apoxy-dev/apoxy-cli/pkg/netstack"
)

var (
	_ Router = (*NetlinkRouter)(nil)
)

// NetlinkRouter implements Router using Linux's netlink subsystem.
type NetlinkRouter struct {
	extLink netlink.Link
	tunDev  tun.Device
	tunLink netlink.Link

	extPrefixes []netip.Prefix

	mux *connip.MuxedConnection
}

func extPrefixes(link netlink.Link) ([]netip.Prefix, error) {
	slog.Info("Checking link", slog.String("name", link.Attrs().Name))

	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for link: %w", err)
	}

	var prefixes []netip.Prefix
	for _, addr := range addrs {
		slog.Debug("Checking address", slog.String("addr", addr.String()))
		// Skip loopback addresses
		ip, ok := netip.AddrFromSlice(addr.IP)
		if !ok {
			slog.Warn("Failed to convert IP address", slog.String("ip", addr.IP.String()))
			continue
		}
		if !ip.Is6() {
			slog.Warn("Skipping non-IPv6 address", slog.String("ip", addr.IP.String()))
			continue
		}
		if !ip.IsGlobalUnicast() { // Skip non-global unicast addresses.
			slog.Debug("Skipping non-global unicast address", slog.String("ip", addr.IP.String()))
			continue
		}

		slog.Info("Found IPv6 address", slog.String("ip", addr.IP.String()), slog.String("mask", addr.Mask.String()))

		bits, _ := addr.Mask.Size()
		prefixes = append(prefixes, netip.PrefixFrom(ip, bits))
	}

	return prefixes, nil
}

// NewNetlinkRouter creates a new netlink-based tunnel router.
// Option represents a router configuration option.
type Option func(*routerOptions)

type routerOptions struct {
	extIfaceName string
	tunIfaceName string
}

func defaultOptions() *routerOptions {
	return &routerOptions{
		extIfaceName: "eth0",
		tunIfaceName: "tun0",
	}
}

// WithExternalInterface sets the external interface name.
func WithExternalInterface(name string) Option {
	return func(o *routerOptions) {
		o.extIfaceName = name
	}
}

// WithTunnelInterface sets the tunnel interface name.
func WithTunnelInterface(name string) Option {
	return func(o *routerOptions) {
		o.tunIfaceName = name
	}
}

// NewNetlinkRouter creates a new netlink-based tunnel router.
func NewNetlinkRouter(opts ...Option) (*NetlinkRouter, error) {
	options := defaultOptions()
	for _, opt := range opts {
		opt(options)
	}

	extLink, err := netlink.LinkByName(options.extIfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get external interface: %w", err)
	}
	lrs, err := extPrefixes(extLink)
	if err != nil {
		return nil, fmt.Errorf("failed to get local routes: %w", err)
	}

	tunDev, err := tun.CreateTUN(options.tunIfaceName, netstack.IPv6MinMTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN interface: %w", err)
	}

	// Get the actual tun name (may differ from requested name).
	actualTunName, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("failed to get TUN interface name: %w", err)
	}

	tunLink, err := netlink.LinkByName(actualTunName)
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("failed to get TUN interface: %w", err)
	}

	if err := netlink.LinkSetUp(tunLink); err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("failed to bring up TUN interface: %w", err)
	}

	return &NetlinkRouter{
		extLink: extLink,

		tunDev:  tunDev,
		tunLink: tunLink,

		extPrefixes: lrs,

		mux: connip.NewMuxedConnection(),
	}, nil
}

const (
	chainName = "A3Y-TUN-RULES"
)

func (r *NetlinkRouter) setupDNAT() error {
	ipt := utiliptables.New(utilexec.New(), utiliptables.ProtocolIPv6)
	exists, err := ipt.EnsureChain(utiliptables.TableNAT, chainName)
	if err != nil {
		return fmt.Errorf("failed to ensure %s chain: %w", chainName, err)
	}
	if exists { // Jump and forwarding rules should be already set up.
		return nil
	}

	extName := r.extLink.Attrs().Name
	tunName := r.tunLink.Attrs().Name

	// Setup jump rule to our custom chain.
	var dsts []string
	for _, prefix := range r.extPrefixes {
		dsts = append(dsts, prefix.Addr().String())
	}
	slices.Sort(dsts)
	slog.Info("Setting up jump rule", slog.String("ext_iface", extName), slog.String("tun_iface", tunName), slog.String("dsts", strings.Join(dsts, ",")))
	jRuleSpec := []string{"-d", strings.Join(dsts, ","), "-i", extName, "-j", chainName}
	if _, err := ipt.EnsureRule(utiliptables.Append, utiliptables.TableNAT, utiliptables.ChainPrerouting, jRuleSpec...); err != nil {
		return fmt.Errorf("failed to ensure jump rule: %w", err)
	}

	// Setup forwarding rules between the external and tunnel interfaces.
	fwdRuleSpecs := [][]string{
		{"-i", extName, "-o", tunName, "-j", "ACCEPT"},
		{"-i", tunName, "-o", extName, "-j", "ACCEPT"},
	}
	slog.Info("Setting up forwarding rules", slog.String("ext_iface", extName), slog.String("tun_iface", tunName))
	for _, ruleSpec := range fwdRuleSpecs {
		if _, err := ipt.EnsureRule(utiliptables.Append, utiliptables.TableFilter, utiliptables.ChainForward, ruleSpec...); err != nil {
			return fmt.Errorf("failed to ensure forwarding rule: %w", err)
		}
	}

	// Setup NAT for traffic returning from the tunnel.
	masqRuleSpec := []string{"-o", extName, "-j", "MASQUERADE"}
	slog.Info("Setting up masquerade rule", slog.String("ext_iface", extName))
	if _, err := ipt.EnsureRule(utiliptables.Append, utiliptables.TableNAT, utiliptables.ChainPostrouting, masqRuleSpec...); err != nil {
		return fmt.Errorf("failed to ensure masquerade rule: %w", err)
	}

	return nil
}

// Start initializes the router and starts forwarding traffic.
func (r *NetlinkRouter) Start(ctx context.Context) error {
	slog.Info("Starting TUN muxer")
	defer slog.Debug("TUN muxer stopped")

	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0644); err != nil {
		return fmt.Errorf("failed to enable IPv6 forwarding: %w", err)
	}

	if err := r.setupDNAT(); err != nil {
		return fmt.Errorf("failed to setup DNAT: %w", err)
	}

	// Create error group with context
	g, gctx := errgroup.WithContext(ctx)

	// Setup cleanup handler
	g.Go(func() error {
		<-gctx.Done()
		slog.Debug("Closing TUN device")
		if err := r.tunDev.Close(); err != nil {
			return fmt.Errorf("failed to close TUN device: %w", err)
		}
		return nil
	})

	// Start the splicing operation
	g.Go(func() error {
		return connip.Splice(r.tunDev, r.mux)
	})

	return g.Wait()
}

func (r *NetlinkRouter) updateDNATRules() error {
	// TBD: save and restore DNAT rules with updated peers.

	return nil
}

// AddPeer adds a peer route to the tunnel.
func (r *NetlinkRouter) AddPeer(peer netip.Prefix, conn connip.Connection) ([]netip.Prefix, error) {
	slog.Debug("Adding route", slog.String("prefix", peer.String()))

	route := &netlink.Route{
		LinkIndex: r.tunLink.Attrs().Index,
		Dst: &net.IPNet{
			IP:   peer.Addr().AsSlice(),
			Mask: net.CIDRMask(peer.Bits(), 128),
		},
		Scope: netlink.SCOPE_LINK,
	}
	if err := netlink.RouteAdd(route); err != nil {
		return nil, fmt.Errorf("failed to add route: %w", err)
	}

	r.mux.AddConnection(peer, conn)

	return r.extPrefixes, nil
}

// RemovePeer removes a peer route from the tunnel.
func (r *NetlinkRouter) RemovePeer(peer netip.Prefix) error {
	slog.Debug("Removing route", slog.String("prefix", peer.String()))

	if err := r.mux.RemoveConnection(peer); err != nil {
		slog.Error("failed to remove connection", err)
	}

	route := &netlink.Route{
		LinkIndex: r.tunLink.Attrs().Index,
		Dst: &net.IPNet{
			IP:   peer.Addr().AsSlice(),
			Mask: net.CIDRMask(peer.Bits(), 128),
		},
		Scope: netlink.SCOPE_LINK,
	}
	if err := netlink.RouteDel(route); err != nil {
		return fmt.Errorf("failed to remove route: %w", err)
	}

	return nil
}

// GetMuxedConnection returns the muxed connection for adding/removing connections.
func (r *NetlinkRouter) GetMuxedConnection() *connip.MuxedConnection {
	return r.mux
}

// Close releases any resources associated with the router.
func (r *NetlinkRouter) Close() error {
	if r.tunDev != nil {
		return r.tunDev.Close()
	}
	return nil
}

package runc

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/metal-stack/go-ipam"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/apoxy-dev/apoxy-cli/pkg/log"
)

const (
	mtuSize = 1500
)

func ethName(prefix, cid string) string {
	return prefix + cid[:8]
}

func setupContainerVeth(cethName string, h netns.NsHandle, v4addr, v4gw netip.Addr, v4prefix netip.Prefix) error {
	ceth, err := netlink.LinkByName(cethName)
	if err != nil {
		return fmt.Errorf("failed to get ceth: %w", err)
	}

	// Move the container side of the veth pair into the container's netns.
	if err := netlink.LinkSetNsFd(ceth, int(h)); err != nil {
		return fmt.Errorf("failed to move ceth into container netns: %w", err)
	}

	nh, err := netlink.NewHandleAt(h)
	if err != nil {
		return fmt.Errorf("failed to create netlink handle: %w", err)
	}
	defer nh.Close()

	// Rename to eth0.
	if err := nh.LinkSetName(ceth, "eth0"); err != nil {
		return fmt.Errorf("failed to rename ceth: %w", err)
	}
	eth0, err := nh.LinkByName("eth0")
	if err != nil {
		return fmt.Errorf("failed to get eth0: %w", err)
	}

	if err := nh.AddrAdd(eth0, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   v4addr.AsSlice(),
			Mask: net.CIDRMask(v4prefix.Bits(), 32),
		},
	}); err != nil {
		return fmt.Errorf("failed to add addr to veth: %w", err)
	}

	// Bring up the container side of the veth pair.
	if err := nh.LinkSetUp(eth0); err != nil {
		return fmt.Errorf("failed to bring up veth: %w", err)
	}

	// Up the loopback interface while we're at it.
	lo, err := nh.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("failed to get loopback interface: %w", err)
	}
	if err := nh.LinkSetUp(lo); err != nil {
		return fmt.Errorf("failed to bring up loopback interface: %w", err)
	}

	if err := nh.RouteAdd(&netlink.Route{
		LinkIndex: eth0.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Gw:        v4gw.AsSlice(),
	}); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}

	return nil
}

func setupVeth(cid string, h netns.NsHandle, v4 *ipam.IP) error {
	// Create the veth pair.
	vp := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: ethName("v", cid),
			MTU:  mtuSize,
		},
		PeerName: ethName("c", cid),
	}
	if err := netlink.LinkAdd(vp); err != nil {
		return fmt.Errorf("failed to create veth pair: %w", err)
	}

	v4net, err := netip.ParsePrefix(v4.ParentPrefix)
	if err != nil {
		return fmt.Errorf("failed to parse prefix: %w", err)
	}

	// For IPv4 default GW needs to be set to the first IP in the subnet.
	v4gw := v4net.Addr().Next()
	if err := setupContainerVeth(vp.PeerName, h, v4.IP, v4gw, v4net); err != nil {
		return fmt.Errorf("failed to setup container veth: %w", err)
	}

	veth, err := netlink.LinkByName(vp.Name)
	if err != nil {
		return fmt.Errorf("failed to get veth: %w", err)
	}
	// Bring up the host side of the veth pair.
	if err := netlink.LinkSetUp(veth); err != nil {
		return fmt.Errorf("failed to bring up veth: %w", err)
	}
	// Set container gateway IP on the host side of the veth pair.
	log.Infof("Setting veth %s IP to %s", vp.Name, v4gw)
	if err := netlink.AddrAdd(veth, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   v4gw.AsSlice(),
			Mask: net.CIDRMask(32, 32),
		},
	}); err != nil {
		return fmt.Errorf("failed to add addr to veth: %w", err)
	}

	// Add host-scope route - this will direct all packets addressed to the container's
	// default IP to the veth pair.
	// TODO(dilyevsky): Will also need to add routes for external IPs allocated
	// the proxy.
	// TODO(dilyevsky): IPv6.
	log.Infof("Adding route for %s", v4gw)
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: veth.Attrs().Index,
		Scope:     netlink.SCOPE_HOST,
		Dst: &net.IPNet{
			IP:   v4.IP.AsSlice(),
			Mask: net.CIDRMask(32, 32),
		},
	}); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}

	return nil
}

//go:build linux
// +build linux

package drivers

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

func getDockerBridgeIP() (string, error) {
	link, err := netlink.LinkByName("docker0")
	if err != nil {
		return "", fmt.Errorf("failed to get docker0 interface: %w", err)
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return "", fmt.Errorf("failed to list addresses for docker0: %w", err)
	}

	if len(addrs) == 0 {
		return "", fmt.Errorf("no addresses found for docker0")
	}

	return addrs[0].IP.String(), nil
}

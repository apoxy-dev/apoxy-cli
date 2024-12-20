package iptables

import (
	"fmt"
)

// SetupContainerNAT sets up NAT rules for a container.
// dev is the name of the device to use for NAT.
func SetupContainerNAT(dev string) error {
	// MASQUERADE all traffic to enable containers to access the internet.
	if err := ipt.AppendUnique("nat", "POSTROUTING", "-o", dev, "-j", "MASQUERADE"); err != nil {
		return fmt.Errorf("failed to append iptables rule: %w", err)
	}

	return nil
}

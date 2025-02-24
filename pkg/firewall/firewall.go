//go:build !linux
// +build !linux

package firewall

import (
	"fmt"

	"github.com/vishvananda/netns"
)

// EnableIPForwarding enables IP forwarding.
func EnableIPForwarding() error {
	return fmt.Errorf("not implemented on this platform")
}

// FlushNAT flushes all NAT rules in the given network namespace.
func FlushNAT(ns netns.NsHandle) error {
	return fmt.Errorf("not implemented on this platform")
}

// EnableNAT sets up NAT rules in the given network namespace to forward packets
// from srcIface to dstIface (names).
func EnableNAT(ns netns.NsHandle, srcIface, dstIface string) error {
	return fmt.Errorf("not implemented on this platform")
}

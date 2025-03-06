//go:build linux
// +build linux

package firewall

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	sysctl "github.com/lorenzosaino/go-sysctl"
	"github.com/vishvananda/netns"
)

// EnableIPForwarding enables IP forwarding.
func EnableIPForwarding() error {
	val, err := sysctl.Get("net.ipv4.ip_forward")
	if err != nil {
		return fmt.Errorf("failed to get IP forwarding status: %w", err)
	}

	// Is it already enabled?
	if val != "1" {
		if err := sysctl.Set("net.ipv4.ip_forward", "1"); err != nil {
			return fmt.Errorf("failed to enable IP forwarding: %w", err)
		}
	}

	return nil
}

// FlushNAT flushes all NAT rules in the given network namespace.
func FlushNAT(ns netns.NsHandle) error {
	conn := nftables.Conn{NetNS: int(ns)}

	nat := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "nat",
	})

	conn.FlushTable(nat)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables ruleset: %w", err)
	}

	return nil
}

// EnableNAT sets up NAT rules in the given network namespace to forward packets
// from srcIface to dstIface (names).
func EnableNAT(ns netns.NsHandle, srcIface, dstIface string) error {
	conn := nftables.Conn{NetNS: int(ns)}

	nat := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "nat",
	})

	post := conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    nat,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})

	conn.AddRule(&nftables.Rule{
		Table: nat,
		Chain: post,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyIIFNAME,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname(srcIface),
			},
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname(dstIface),
			},
			&expr.Masq{},
		},
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables ruleset: %w", err)
	}

	return nil
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}

// Package iptables container useful routines for manipulating iptables rules.
package iptables

import (
	"flag"
	"fmt"
	"os/exec"

	"github.com/coreos/go-iptables/iptables"

	"github.com/apoxy-dev/apoxy/pkg/log"
)

// TODO(dilyevsky): Interface this out so we can mock it in tests.
var (
	ipt *iptables.IPTables

	useLegacy = flag.Bool("iptables-use-legacy", false, "Use legacy iptables.")
)

func init() {
	if *useLegacy {
		log.Infof("Using legacy iptables")
		cmd := exec.Command("update-alternatives", "--set", "iptables", "/usr/sbin/iptables-legacy")
		if err := cmd.Run(); err != nil {
			panic(fmt.Sprintf("failed to set iptables to legacy: %v", err))
		}
		cmd = exec.Command("update-alternatives", "--set", "ip6tables", "/usr/sbin/ip6tables-legacy")
		if err := cmd.Run(); err != nil {
			panic(fmt.Sprintf("failed to set ip6tables to legacy: %v", err))
		}
	}
	var err error
	ipt, err = iptables.New(iptables.Path("/sbin/iptables"))
	if err != nil {
		panic(fmt.Sprintf("failed to create iptables: %v", err))
	}
}

// GetIptables returns the iptables instance.
func GetIptables() *iptables.IPTables {
	return ipt
}

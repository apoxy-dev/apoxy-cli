package net

import (
	"errors"
	"log/slog"
	gonet "net"
	"net/netip"
	"sort"
)

// LocalRouteIPv6 finds the local IPv6 address and returns it as a netip.Prefix.
func LocalRouteIPv6() (netip.Prefix, error) {
	ifaces, err := gonet.Interfaces()
	if err != nil {
		return netip.Prefix{}, err
	}

	var prefixes []netip.Prefix
	for _, iface := range ifaces {
		if iface.Flags&gonet.FlagUp == 0 {
			continue
		}

		slog.Debug("Checking interface", slog.String("name", iface.Name))

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			slog.Debug("Checking address", slog.String("addr", addr.String()))
			// Check if address is IP network
			if ipnet, ok := addr.(*gonet.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() == nil {
				slog.Info("Found IPv6 address", slog.String("ip", ipnet.IP.String()))
				bits, _ := ipnet.Mask.Size()
				prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom16([16]byte(ipnet.IP.To16())), bits))
			}
		}
	}

	// Pick the most specific prefix first (giving priority to ULA addresses).
	sort.SliceStable(prefixes, func(i, j int) bool {
		ulaI, ulaJ := isULA(prefixes[i].Addr()), isULA(prefixes[j].Addr())
		if ulaI != ulaJ {
			return ulaI
		}
		return prefixes[i].Bits() > prefixes[j].Bits()
	})

	if len(prefixes) > 0 {
		return prefixes[0], nil
	}

	return netip.Prefix{}, errors.New("no IP address found")
}

// isULA checks if the given address is a Unique Local Address (ULA).
func isULA(addr netip.Addr) bool {
	ulaRange := netip.MustParsePrefix("fc00::/7")
	if addr.Is6() && ulaRange.Contains(addr) {
		return true
	}
	return false
}

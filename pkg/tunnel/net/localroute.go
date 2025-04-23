package net

import (
	"log/slog"
	gonet "net"
	"net/netip"
)

// LocalIPv6Routes finds the local IPv6 address and returns it as a netip.Prefix.
func LocalIPv6Routes() ([]netip.Prefix, error) {
	ifaces, err := gonet.Interfaces()
	if err != nil {
		return nil, err
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

	return prefixes, nil
}

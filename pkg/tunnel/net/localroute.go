package net

import (
	"errors"
	"log/slog"
	gonet "net"
	"net/netip"
)

// LocalRouteIPv6 finds the local IPv6 address and returns it as a netip.Prefix.
func LocalRouteIPv6() (netip.Prefix, error) {
	ifaces, err := gonet.Interfaces()
	if err != nil {
		return netip.Prefix{}, err
	}

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
				return netip.PrefixFrom(netip.AddrFrom16([16]byte(ipnet.IP.To16())), bits), nil
			}
		}
	}

	return netip.Prefix{}, errors.New("no IP address found")
}

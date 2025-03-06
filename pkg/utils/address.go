package utils

import "net/netip"

// FirstValidAddress returns the first valid address in the given network.
func FirstValidAddress(prefix netip.Prefix) netip.Addr {
	first := prefix.Addr()
	if first.Is4() && prefix.Bits() < 31 {
		return first.Next()
	}
	return first
}

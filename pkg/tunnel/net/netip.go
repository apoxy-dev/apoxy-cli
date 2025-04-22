package net

import "net/netip"

// LastIP returns the last IP address in the given prefix.
func LastIP(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr()
	bytes := addr.AsSlice()

	hostBits := len(bytes)*8 - prefix.Bits()
	for i := len(bytes) - 1; i >= 0; i-- {
		setBits := min(8, hostBits)
		if setBits <= 0 {
			break
		}
		bytes[i] |= byte(0xff >> (8 - setBits))
		hostBits -= 8
	}

	if addr.Is4() {
		return netip.AddrFrom4([4]byte(bytes[:4]))
	}
	return netip.AddrFrom16([16]byte(bytes))
}

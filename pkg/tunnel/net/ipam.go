package net

import (
	"crypto/rand"
	"net/http"
	"net/netip"
)

type IPAM interface {
	// Allocate allocates an IP address for a peer.
	Allocate(r *http.Request) netip.Prefix

	// Release releases an IP address for a peer. No-op if the address is not allocated
	// (returns nil).
	Release(peerPrefix netip.Prefix) error
}

type randomULA struct {
}

func NewRandomULA() IPAM {
	return &randomULA{}
}

func (r *randomULA) Allocate(_ *http.Request) netip.Prefix {
	addr := apoxyULAPrefix.Addr().As16()
	// Generate 6 random bytes (48 bits) - this will fill the bits between /48 and /96
	var randomBytes [6]byte
	_, _ = rand.Read(randomBytes[:])

	// Insert the random bytes into positions 6-11 (after the /48 prefix, before the /96 suffix)
	for i := 0; i < 6; i++ {
		addr[6+i] = randomBytes[i]
	}

	// Create a new IPv6 address from the modified bytes
	randomAddr := netip.AddrFrom16(addr)

	// Return as a /96 prefix
	return netip.PrefixFrom(randomAddr, 96)
}

func (r *randomULA) Release(_ netip.Prefix) error {
	return nil
}

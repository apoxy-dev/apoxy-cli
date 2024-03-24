package wg

import (
	"hash/fnv"
	"net/netip"
	"sync"

	"github.com/google/uuid"
)

const (
	apoxyULAPrefix = "fd61:706f:7879::/48"
	//addr           = "fd61:706f:7879:oooo:oooo:eeee:127.0.0.1/128"
)

var (
	oncePrefix4To6 oncePrefix
)

type oncePrefix struct {
	sync.Once
	prefix netip.Prefix
}

// Apoxy4To6Range returns the Unique Local Adddres prefix used by Apoxy for IPv4 to IPv6
// translation.
func Apoxy4To6Range() netip.Prefix {
	oncePrefix4To6.Do(func() {
		oncePrefix4To6.prefix = netip.MustParsePrefix(apoxyULAPrefix)
	})
	return oncePrefix4To6.prefix
}

// NewApoxy4To6Prefix generates a new IPv6 address from the Apoxy4To6Range prefix.
func NewApoxy4To6Prefix(orgID uuid.UUID, endpoint string) netip.Prefix {
	addr := Apoxy4To6Range().Addr().As16()
	// fnv hash of the orgID and endpoint
	o := fnv.New32()
	o.Write(orgID[:])
	copy(addr[6:], o.Sum(nil))

	e := fnv.New32()
	e.Write([]byte(endpoint))
	// We only need 16 bits of the hash so recommendation is to do XOR-folding
	// http://www.isthe.com/chongo/tech/comp/fnv/#xor-fold
	mask := uint32(0xffff)
	h := e.Sum32()>>16 ^ e.Sum32()&mask
	addr[10] = byte(h >> 8)
	addr[11] = byte(h)

	return netip.PrefixFrom(netip.AddrFrom16(addr), 96)
}

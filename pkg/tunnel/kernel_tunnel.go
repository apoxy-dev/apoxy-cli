//go:build !linux
// +build !linux

package tunnel

import (
	"errors"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
)

// CreateKernelTunnel creates a new kernel tunnel interface (WireGuard).
func CreateKernelTunnel(
	addr netip.Prefix,
	bind conn.Bind,
	verbose bool,
) (Tunnel, error) {
	return nil, errors.New("kernel mode tunnel is not supported on this platform")
}

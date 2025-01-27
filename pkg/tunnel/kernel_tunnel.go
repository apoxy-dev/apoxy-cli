//go:build !linux
// +build !linux

package tunnel

import (
	"context"
	"errors"
)

// CreateKernelTunnel creates a new kernel tunnel interface (WireGuard).
func CreateKernelTunnel(
	ctx context.Context,
) (Tunnel, error) {
	return nil, errors.New("kernel mode tunnel is not supported on this platform")
}

//go:build !linux
// +build !linux

package tunnel

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// CreateKernelTunnel creates a new kernel tunnel interface (WireGuard).
func CreateKernelTunnel(
	ctx context.Context,
	projectID uuid.UUID,
	endpoint string,
) (Tunnel, error) {
	return nil, errors.New("kernel mode tunnel is not supported on this platform")
}

//go:build !linux
// +build !linux

package wireguard

import (
	"errors"
)

type KernelModeTransport struct {
	TunnelTransport
}

// NewKernelModeNetwork returns a new kernel mode wireguard network.
func NewKernelModeTransport(
	conf *DeviceConfig,
) (*KernelModeTransport, error) {
	return &KernelModeTransport{}, errors.New("kernel mode networks are not supported on this platform")
}

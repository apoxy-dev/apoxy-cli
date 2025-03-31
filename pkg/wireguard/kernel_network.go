//go:build !linux
// +build !linux

package wireguard

import (
	"errors"
)

type KernelModeNetwork struct {
	Network
}

// NewKernelModeNetwork returns a new kernel mode wireguard network.
func NewKernelModeNetwork(
	conf *DeviceConfig,
) (*KernelModeNetwork, error) {
	return &KernelModeNetwork{}, errors.New("kernel mode networks are not supported on this platform")
}

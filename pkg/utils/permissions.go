//go:build !linux

package utils

// IsNetAdmin checks if the current user has NET_ADMIN capabilities.
// NET_ADMIN is required to create TUN devices and configure routes etc.
// This is a placeholder implementation for non-Linux systems.
func IsNetAdmin() (bool, error) {
	return false, nil
}

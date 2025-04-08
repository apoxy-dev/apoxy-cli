//go:build !linux

package utils

func CanCreateTUNInterfaces() (bool, error) {
	return false, nil
}

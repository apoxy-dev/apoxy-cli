//go:build !linux

package router

import "fmt"

func NewNetlinkRouter(_ ...Option) (Router, error) {
	return nil, fmt.Errorf("netlink router is not supported on this platform")
}

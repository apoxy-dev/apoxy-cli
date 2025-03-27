// Package drivers implements Backplane drivers (e.g Docker, Kubernetes, etc.)
package drivers

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// Option is a function that configures driver options.
type Option func(*Options)

// Options contains common options for all drivers.
type Options struct {
	Args []string
}

// DefaultOptions returns the default options.
func DefaultOptions() *Options {
	return &Options{}
}

// WithArgs sets the arguments for the driver.
func WithArgs(args ...string) Option {
	return func(o *Options) {
		o.Args = args
	}
}

// Driver is the interface that all backplane drivers must implement.
type Driver interface {
	// Start deploys and starts the backplane.
	Start(ctx context.Context, orgID uuid.UUID, proxyName string, opts ...Option) (string, error)
	// Stop stops the backplane.
	Stop(orgID uuid.UUID, proxyName string)
}

// GetDriver returns a driver by name.
func GetDriver(driver string) (Driver, error) {
	switch driver {
	case "docker":
		return NewDockerDriver(), nil
	case "supervisor":
		return NewSupervisorDriver(), nil
	default:
		return nil, fmt.Errorf("unknown driver %q", driver)
	}
}

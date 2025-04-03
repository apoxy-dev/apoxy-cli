// Package drivers implements common interfaces and utilities for Apoxy service drivers
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
	Args          []string
	APIServerAddr string
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

// WithAPIServerAddr sets the apiserver address.
func WithAPIServerAddr(addr string) Option {
	return func(o *Options) {
		o.APIServerAddr = addr
	}
}

// Driver is the interface that all service drivers must implement.
type Driver interface {
	// Start deploys and starts the service.
	Start(ctx context.Context, orgID uuid.UUID, serviceName string, opts ...Option) (string, error)
	// Stop stops the service.
	Stop(orgID uuid.UUID, serviceName string)
	// GetAddr returns the address of the service.
	GetAddr(ctx context.Context) (string, error)
}

// ServiceType represents the type of service being managed by a driver.
type ServiceType string

// DriverMode represents the mode in which the driver is running.
type DriverMode string

const (
	// BackplaneService represents the backplane service.
	BackplaneService ServiceType = "backplane"
	// APIServerService represents the apiserver service.
	APIServerService ServiceType = "apiserver"

	// DockerMode represents the docker driver mode.
	DockerMode DriverMode = "docker"
	// SupervisorMode represents the supervisor driver mode.
	SupervisorMode DriverMode = "supervisor"
)

// GetDriver returns a driver by name for the specified service type.
func GetDriver(driverType DriverMode, serviceType ServiceType) (Driver, error) {
	switch serviceType {
	case BackplaneService:
		return GetBackplaneDriver(driverType)
	case APIServerService:
		return GetAPIServerDriver(driverType)
	default:
		return nil, fmt.Errorf("unknown service type %q", serviceType)
	}
}

// GetBackplaneDriver returns a backplane driver by name.
func GetBackplaneDriver(driver DriverMode) (Driver, error) {
	switch driver {
	case DockerMode:
		return NewBackplaneDockerDriver(), nil
	case SupervisorMode:
		return NewBackplaneSupervisorDriver(), nil
	default:
		return nil, fmt.Errorf("unknown backplane driver %q", driver)
	}
}

// GetAPIServerDriver returns an apiserver driver by name.
func GetAPIServerDriver(driver DriverMode) (Driver, error) {
	switch driver {
	case DockerMode:
		return NewAPIServerDockerDriver(), nil
	case SupervisorMode:
		return NewAPIServerSupervisorDriver(), nil
	default:
		return nil, fmt.Errorf("unknown apiserver driver %q", driver)
	}
}

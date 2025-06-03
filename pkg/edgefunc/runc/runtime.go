package runc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/apoxy-dev/apoxy/pkg/edgefunc"
	"github.com/apoxy-dev/apoxy/pkg/edgefunc/runc/network"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

type Option func(*options)

type options struct {
	runtimeBinPath string
	baseDir        string
	hostIPv4CIDR   string
	hostIPv6CIDR   string
}

func defaultOptions() *options {
	return &options{
		runtimeBinPath: "/bin/edge-runtime",
		baseDir:        "/run/edgefuncs",
		hostIPv4CIDR:   "192.168.100.0/24",
		hostIPv6CIDR:   "fd00::/64",
	}
}

func WithRuntimeBinPath(p string) Option {
	return func(o *options) {
		o.runtimeBinPath = p
	}
}

func WithWorkDir(p string) Option {
	return func(o *options) {
		o.baseDir = p
	}
}

type runtime struct {
	runtimeBinPath        string
	stateDir, rootBaseDir string
	net                   *network.Network
}

// NewRuntime returns a new edgefunc.Runtime implementation based on runc.
func NewRuntime(ctx context.Context, opts ...Option) (edgefunc.Runtime, error) {
	runtimeOpts := defaultOptions()
	for _, o := range opts {
		o(runtimeOpts)
	}

	log.Infof("Creating edge-runtime container runtime...")
	log.Infof("Initializing state dirs...")

	if err := os.MkdirAll(runtimeOpts.baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create work directory: %w", err)
	}
	stateDir := filepath.Join(runtimeOpts.baseDir, "state")
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create state directory: %w", err)
	}
	rootBaseDir := filepath.Join(runtimeOpts.baseDir, "rootfs")
	if err := os.MkdirAll(rootBaseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create rootFS directory: %w", err)
	}

	if _, err := os.Stat(runtimeOpts.runtimeBinPath); err != nil {
		fmt.Errorf("edge-runtime binary not found at %s", runtimeOpts.runtimeBinPath)
	}

	cnet := network.NewNetwork()
	if err := cnet.Init(ctx); err != nil {
		return nil, fmt.Errorf("failed to load network: %w", err)
	}

	return &runtime{
		runtimeBinPath: runtimeOpts.runtimeBinPath,
		stateDir:       stateDir,
		rootBaseDir:    rootBaseDir,
		net:            cnet,
	}, nil
}

// Run initaliazes and runs the runtime bookkeeping loop.
// It will block until the context is cancelled.
func (r *runtime) Run(ctx context.Context) error {
	log.Infof("Starting runc runtime...")

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			// TODO(dilyevsky): Implement.
		}
	}
	panic("unreachable")
}

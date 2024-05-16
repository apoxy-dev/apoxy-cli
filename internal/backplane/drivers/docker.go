// Package drivers implements Backplane drivers (e.g Docker, Kubernetes, etc.)
package drivers

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/google/uuid"

	"github.com/apoxy-dev/apoxy-cli/build"
	"github.com/apoxy-dev/apoxy-cli/internal/log"
	dockerutils "github.com/apoxy-dev/apoxy-cli/internal/utils/docker"
)

const (
	containerNamePrefix = "apoxy-backplane-"
	imageRepo           = "docker.io/apoxy/backplane"
)

type Option func(*options)

type options struct {
	Args []string
}

func defaultOptions() *options {
	return &options{}
}

// WithArgs sets the arguments for the driver.
func WithArgs(args ...string) Option {
	return func(o *options) {
		o.Args = args
	}
}

type Driver interface {
	// Deploy deploys the proxy.
	Start(ctx context.Context, orgID uuid.UUID, proxyName string, opts ...Option) error
}

// GetDriver returns a driver by name.
func GetDriver(driver string) (Driver, error) {
	switch driver {
	case "docker":
		return &dockerDriver{}, nil
	}
	return nil, fmt.Errorf("unknown driver %q", driver)
}

type dockerDriver struct{}

func imageRef() string {
	imgTag := build.BuildVersion
	if build.IsDev() {
		imgTag = "latest"
	}
	return imageRepo + ":" + imgTag
}

func (d *dockerDriver) Start(
	ctx context.Context,
	orgID uuid.UUID,
	proxyName string,
	opts ...Option,
) error {
	setOpts := defaultOptions()
	for _, opt := range opts {
		opt(setOpts)
	}
	imageRef := imageRef()
	cname, found, err := dockerutils.Collect(
		ctx, containerNamePrefix, imageRef, dockerutils.WithLabel("org.apoxy.machine", proxyName))
	if err != nil {
		return err
	} else if found {
		log.Infof("Container %s already running", cname)
		return nil
	}

	// Pull the image.
	if err := exec.CommandContext(ctx, "docker", "pull", imageRef).Run(); err != nil {
		return fmt.Errorf("failed to pull image %s: %w", imageRef, err)
	}

	// Check for network and create if not exists.
	if err := exec.CommandContext(ctx, "docker", "network", "inspect", dockerutils.NetworkName).Run(); err != nil {
		if err := exec.CommandContext(ctx, "docker", "network", "create", dockerutils.NetworkName).Run(); err != nil {
			return fmt.Errorf("failed to create network apoxy: %w", err)
		}
	}

	log.Infof("Starting container %s", cname)
	cmd := exec.CommandContext(ctx,
		"docker", "run",
		"--rm",
		"--name", cname,
		"--label", "org.apoxy.machine="+proxyName,
		"--privileged",
		"--network", dockerutils.NetworkName,
	)

	cmd.Args = append(cmd.Args, imageRef)
	cmd.Args = append(cmd.Args, []string{
		"--project_id=" + orgID.String(),
		"--proxy_name=" + proxyName,
		"--apiserver_host=host.docker.internal",
	}...)
	cmd.Args = append(cmd.Args, setOpts.Args...)

	log.Debugf("Running command: %v", cmd.String())

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start clickhouse server: %w", err)
	}

	if err := dockerutils.WaitForStatus(ctx, cname, "running"); err != nil {
		return fmt.Errorf("failed to start clickhouse server: %w", err)
	}

	return nil
}

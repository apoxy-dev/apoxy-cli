// Package drivers implements Backplane drivers (e.g Docker, Kubernetes, etc.)
package drivers

import (
	"context"
	"fmt"
	"net"
	"os/exec"

	"github.com/google/uuid"

	"github.com/apoxy-dev/apoxy-cli/build"
	"github.com/apoxy-dev/apoxy-cli/pkg/log"
	"github.com/apoxy-dev/apoxy-cli/pkg/utils"
	dockerutils "github.com/apoxy-dev/apoxy-cli/pkg/utils/docker"
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
	Start(ctx context.Context, orgID uuid.UUID, proxyName string, opts ...Option) (string, error)
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
) (string, error) {
	setOpts := defaultOptions()
	for _, opt := range opts {
		opt(setOpts)
	}
	imageRef := imageRef()
	cname, found, err := dockerutils.Collect(
		ctx,
		containerNamePrefix,
		imageRef,
		dockerutils.WithLabel("org.apoxy.projec_id", orgID.String()),
		dockerutils.WithLabel("org.apoxy.proxy", proxyName),
	)
	if err != nil {
		return "", err
	} else if found {
		log.Infof("Container %s already running", cname)
		return cname, nil
	}

	// Check if we have the image.
	if err := exec.CommandContext(ctx, "docker", "image", "inspect", imageRef).Run(); err != nil {
		// If not, pull it.
		if err := exec.CommandContext(ctx, "docker", "pull", imageRef).Run(); err != nil {
			return "", fmt.Errorf("failed to pull image %s: %w", imageRef, err)
		}
	}

	// Check for network and create if not exists.
	if err := exec.CommandContext(ctx, "docker", "network", "inspect", dockerutils.NetworkName).Run(); err != nil {
		if err := exec.CommandContext(ctx, "docker", "network", "create", dockerutils.NetworkName).Run(); err != nil {
			return "", fmt.Errorf("failed to create network apoxy: %w", err)
		}
	}

	log.Infof("Starting container %s", cname)
	cmd := exec.CommandContext(ctx,
		"docker", "run",
		"--pull=always",
		"--detach",
		//"--rm",
		"--name", cname,
		"--label", "org.apoxy.project_id="+orgID.String(),
		"--label", "org.apoxy.proxy="+proxyName,
		"--privileged",
		"--network", dockerutils.NetworkName,
	)

	apiServerHost, err := getDockerBridgeIP()
	if err != nil {
		return "", fmt.Errorf("failed to get docker bridge IP: %w", err)
	}

	cmd.Args = append(cmd.Args, imageRef)
	cmd.Args = append(cmd.Args, []string{
		"--project_id=" + orgID.String(),
		// Use the same name for both proxy and replica - we only have one replica.
		"--proxy=" + proxyName,
		"--replica=" + proxyName,
		"--apiserver_addr=" + net.JoinHostPort(apiServerHost, "8443"),
		"--envoy_release_url=https://apoxy-envoy-releases.s3.us-west-2.amazonaws.com/envoy-contrib-dev-cfedcdbc0bf1e687d0fc2ad243e7277ed004673d-" + utils.HostArch(),
		"--use_envoy_contrib=true",
	}...)
	cmd.Args = append(cmd.Args, setOpts.Args...)

	log.Debugf("Running command: %v", cmd.String())

	if err := cmd.Run(); err != nil {
		if execErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("failed to start Envoy backplane: %s", execErr.Stderr)
		}
		return "", fmt.Errorf("failed to start Envoy backplane: %w", err)
	}

	if err := dockerutils.WaitForStatus(ctx, cname, "running"); err != nil {
		return "", fmt.Errorf("failed to start Envoy backplane: %w", err)
	}

	return cname, nil
}

package drivers

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"time"

	"github.com/google/uuid"

	"github.com/apoxy-dev/apoxy-cli/build"
	"github.com/apoxy-dev/apoxy-cli/pkg/log"
	dockerutils "github.com/apoxy-dev/apoxy-cli/pkg/utils/docker"
)

const (
	containerNamePrefix = "apoxy-backplane-"
	imageRepo           = "docker.io/apoxy/backplane"
)

// DockerDriver implements the Driver interface for Docker.
type DockerDriver struct{}

// NewDockerDriver creates a new Docker driver.
func NewDockerDriver() *DockerDriver {
	return &DockerDriver{}
}

func imageRef() string {
	imgTag := build.BuildVersion
	if build.IsDev() {
		imgTag = "latest"
	}
	return imageRepo + ":" + imgTag
}

// Start implements the Driver interface.
func (d *DockerDriver) Start(
	ctx context.Context,
	orgID uuid.UUID,
	proxyName string,
	opts ...Option,
) (string, error) {
	setOpts := DefaultOptions()
	for _, opt := range opts {
		opt(setOpts)
	}
	imageRef := imageRef()
	cname, found, err := dockerutils.Collect(
		ctx,
		containerNamePrefix,
		imageRef,
		dockerutils.WithLabel("org.apoxy.project_id", orgID.String()),
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
	pullPolicy := "missing"
	if build.IsDev() {
		pullPolicy = "always"
	}
	cmd := exec.CommandContext(ctx,
		"docker", "run",
		fmt.Sprintf("--pull=%s", pullPolicy),
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

// Stop implements the Driver interface.
func (d *DockerDriver) Stop(orgID uuid.UUID, proxyName string) {
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	imageRef := imageRef()
	cname, found, err := dockerutils.Collect(
		ctx,
		containerNamePrefix,
		imageRef,
		dockerutils.WithLabel("org.apoxy.project_id", orgID.String()),
		dockerutils.WithLabel("org.apoxy.proxy", proxyName),
	)
	if err != nil {
		log.Errorf("Error stopping Docker container: %v", err)
	} else if !found {
		log.Infof("Container %s wasn't found running", cname)
		return
	}
	log.Infof("Stopping container %s", cname)
	cmd := exec.CommandContext(ctx,
		"docker", "rm", "-f", cname,
	)
	if err := cmd.Run(); err != nil {
		if execErr, ok := err.(*exec.ExitError); ok {
			log.Errorf("failed to stop Envoy backplane: %s", execErr.Stderr)
		} else {
			log.Errorf("failed to stop Envoy backplane: %v", err)
		}
	}
}

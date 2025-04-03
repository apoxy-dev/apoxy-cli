package drivers

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/google/uuid"

	"github.com/apoxy-dev/apoxy-cli/build"
	"github.com/apoxy-dev/apoxy-cli/pkg/log"
	dockerutils "github.com/apoxy-dev/apoxy-cli/pkg/utils/docker"
)

const (
	apiserverContainerNamePrefix = "apoxy-apiserver-"
	apiserverImageRepo           = "docker.io/apoxy/apiserver"
)

// APIServerDockerDriver implements the Driver interface for Docker.
type APIServerDockerDriver struct{}

// NewAPIServerDockerDriver creates a new Docker driver for apiserver.
func NewAPIServerDockerDriver() *APIServerDockerDriver {
	return &APIServerDockerDriver{}
}

func apiserverImageRef() string {
	imgTag := build.BuildVersion
	if build.IsDev() {
		imgTag = "latest"
	}
	return apiserverImageRepo + ":" + imgTag
}

// Start implements the Driver interface.
func (d *APIServerDockerDriver) Start(
	ctx context.Context,
	orgID uuid.UUID,
	serviceName string,
	opts ...Option,
) (string, error) {
	setOpts := DefaultOptions()
	for _, opt := range opts {
		opt(setOpts)
	}
	imageRef := apiserverImageRef()
	cname, found, err := dockerutils.Collect(
		ctx,
		apiserverContainerNamePrefix,
		imageRef,
		dockerutils.WithLabel("org.apoxy.project_id", orgID.String()),
		dockerutils.WithLabel("org.apoxy.apiserver", serviceName),
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
		"--name", cname,
		"--label", "org.apoxy.project_id="+orgID.String(),
		"--label", "org.apoxy.apiserver="+serviceName,
		"--network", dockerutils.NetworkName,
		"-p", "8443:8443", // Expose API server port
		"-p", "8081:8081", // Expose ingest store port
	)

	cmd.Args = append(cmd.Args, imageRef)

	// Add standard arguments
	cmd.Args = append(cmd.Args, []string{
		"--dev=true",
	}...)

	// Add user-provided arguments
	cmd.Args = append(cmd.Args, setOpts.Args...)

	log.Debugf("Running command: %v", cmd.String())

	if err := cmd.Run(); err != nil {
		if execErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("failed to start API server: %s", execErr.Stderr)
		}
		return "", fmt.Errorf("failed to start API server: %w", err)
	}

	if err := dockerutils.WaitForStatus(ctx, cname, "running"); err != nil {
		return "", fmt.Errorf("failed to start API server: %w", err)
	}

	return cname, nil
}

// Stop implements the Driver interface.
func (d *APIServerDockerDriver) Stop(orgID uuid.UUID, serviceName string) {
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	imageRef := apiserverImageRef()
	cname, found, err := dockerutils.Collect(
		ctx,
		apiserverContainerNamePrefix,
		imageRef,
		dockerutils.WithLabel("org.apoxy.project_id", orgID.String()),
		dockerutils.WithLabel("org.apoxy.apiserver", serviceName),
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
			log.Errorf("failed to stop API server: %s", execErr.Stderr)
		} else {
			log.Errorf("failed to stop API server: %v", err)
		}
	}
}

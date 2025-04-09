package drivers

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/google/uuid"

	"github.com/apoxy-dev/apoxy-cli/pkg/log"
	dockerutils "github.com/apoxy-dev/apoxy-cli/pkg/utils/docker"
)

const (
	apiserverContainerNamePrefix = "apoxy-apiserver-"
	apiserverImageRepo           = "apiserver"
)

// APIServerDockerDriver implements the Driver interface for Docker.
type APIServerDockerDriver struct {
	dockerDriverBase
}

// NewAPIServerDockerDriver creates a new Docker driver for apiserver.
func NewAPIServerDockerDriver() *APIServerDockerDriver {
	return &APIServerDockerDriver{}
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

	if err := d.Init(ctx, opts...); err != nil {
		return "", err
	}

	imageRef := d.ImageRef(apiserverImageRepo)
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

	if err := exec.CommandContext(ctx, "docker", "image", "inspect", imageRef).Run(); err != nil {
		if err := exec.CommandContext(ctx, "docker", "pull", imageRef).Run(); err != nil {
			return "", fmt.Errorf("failed to pull image %s: %w", imageRef, err)
		}
	}

	log.Infof("Starting container %s", cname)

	cmd := exec.CommandContext(ctx,
		"docker", "run",
		fmt.Sprintf("--pull=%s", d.PullPolicy()),
		"--detach",
		"--name", cname,
		"--label", "org.apoxy.project_id="+orgID.String(),
		"--label", "org.apoxy.apiserver="+serviceName,
		"--network", dockerutils.NetworkName,
		"-p", "8443:8443", // Expose API server port.
		"-p", "8081:8081", // Expose ingest store port.
	)

	cmd.Args = append(cmd.Args, imageRef)

	cmd.Args = append(cmd.Args, []string{
		"--dev=true",
	}...)

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

	if err := healthCheckAPIServer(); err != nil {
		return "", err
	}

	return cname, nil
}

// Stop implements the Driver interface.
func (d *APIServerDockerDriver) Stop(orgID uuid.UUID, serviceName string) {
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	imageRef := d.ImageRef(apiserverImageRepo)
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

// GetAddr implements the Driver interface.
func (d *APIServerDockerDriver) GetAddr(ctx context.Context) (string, error) {
	cname, found, err := dockerutils.Collect(
		ctx,
		apiserverContainerNamePrefix,
		d.ImageRef(apiserverImageRepo),
	)
	if err != nil {
		return "", err
	} else if !found {
		return "", fmt.Errorf("apiserver not found")
	}
	return cname, nil
}

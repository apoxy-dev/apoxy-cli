package drivers

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/google/uuid"

	"github.com/apoxy-dev/apoxy/pkg/log"
	dockerutils "github.com/apoxy-dev/apoxy/pkg/utils/docker"
)

const (
	dockerNetwork = "apoxy"

	ratelimitImage        = "docker.io/apoxy/ratelimit:efa7eaf9ed"
	rlContainerNamePrefix = "apoxy-ratelimit-"

	redisImage               = "docker.io/library/redis:6.2.5"
	redisContainerNamePrefix = "apoxy-redis-"
)

// Driver is the interface to deploy RateLimit service.
type Driver interface {
	// Starts the RateLimit service.
	Start(ctx context.Context, orgID uuid.UUID, xdsURL string) error
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

func waitForRedis(ctx context.Context, cname string) error {
	for {
		cmd := exec.CommandContext(ctx,
			"docker", "exec",
			cname,
			"redis-cli",
			"ping",
		)
		if err := cmd.Run(); err == nil {
			return nil
		}
		log.Infof("redis server is not ready, waiting...")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	panic("unreachable")
}

func (d *dockerDriver) setupRedis(ctx context.Context, orgID uuid.UUID) (string, error) {
	cname, found, err := dockerutils.Collect(
		ctx,
		redisContainerNamePrefix,
		redisImage,
		dockerutils.WithLabel("org.apoxy.project_id", orgID.String()),
	)
	if err != nil {
		return "", fmt.Errorf("failed to collect redis server: %w", err)
	} else if found {
		log.Infof("redis server is already running: %s", cname)
		return cname, nil
	}

	log.Infof("starting redis server...")

	cmd := exec.CommandContext(ctx,
		"docker", "run",
		"--detach",
		"--rm",
		"--name", cname,
		"--label", "org.apoxy.project_id="+orgID.String(),
		"--network", dockerNetwork,
		"-p", "6379:6379",
		redisImage,
	)

	log.Infof("running command: %v", cmd.Args)

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("failed to start redis server: %v", exitErr.Stderr)
		}
		return "", fmt.Errorf("failed to start redis server: %w", err)
	}

	if err := dockerutils.WaitForStatus(ctx, cname, "running"); err != nil {
		return "", fmt.Errorf("failed to start redis server: %w", err)
	}

	if err := waitForRedis(ctx, cname); err != nil {
		return "", fmt.Errorf("failed to start redis server: %w", err)
	}

	log.Infof("redis server is running: %s", cname)

	return cname, nil
}

// Start starts the RateLimit service container in Docker.
func (d *dockerDriver) Start(ctx context.Context, orgID uuid.UUID, xdsURL string) error {
	// Check for network and create if not exists.
	if err := exec.CommandContext(ctx, "docker", "network", "inspect", dockerutils.NetworkName).Run(); err != nil {
		if err := exec.CommandContext(ctx, "docker", "network", "create", dockerutils.NetworkName).Run(); err != nil {
			return fmt.Errorf("failed to create network apoxy: %w", err)
		}
	}

	rc, err := d.setupRedis(ctx, orgID)
	if err != nil {
		return fmt.Errorf("failed to setup redis: %w", err)
	}

	cname, found, err := dockerutils.Collect(
		ctx,
		rlContainerNamePrefix,
		ratelimitImage,
		dockerutils.WithLabel("org.apoxy.project_id", orgID.String()),
	)
	if err != nil {
		return err
	} else if found {
		log.Infof("ratelimit server is already running: %s", cname)
		return nil
	}

	log.Infof("starting ratelimite service...")

	cmd := exec.CommandContext(ctx,
		"docker", "run",
		"--detach",
		"--rm",
		"--name", cname,
		"--label", "org.apoxy.project_id="+orgID.String(),
		"--network", dockerutils.NetworkName,
		"-e", "REDIS_SOCKET_TYPE=tcp",
		"-e", fmt.Sprintf("REDIS_URL=%s:6379", rc),
		"-e", "USE_STATSD=false",
		"-e", "LOG_LEVEL=debug",
		"-e", "CONFIG_TYPE=GRPC_XDS_SOTW",
		"-e", "CONFIG_GRPC_XDS_NODE_ID="+orgID.String(),
		"-e", "FORCE_START_WITHOUT_INITIAL_CONFIG=true",
		"-e", "CONFIG_GRPC_XDS_SERVER_URL="+xdsURL,
		//"-p", "8080:8080",
		//"-p", "8081:8081",
		//"-p", "6070:6070",
		ratelimitImage,
	)

	log.Debugf("running command: %v", cmd.Args)

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("failed to start clickhouse server: %v", exitErr.Stderr)
		}
		return fmt.Errorf("failed to start clickhouse server: %w", err)
	}

	if err := dockerutils.WaitForStatus(ctx, cname, "running"); err != nil {
		return fmt.Errorf("failed to start clickhouse server: %w", err)
	}

	log.Infof("ratelimit server is running: %s", cname)

	return nil
}

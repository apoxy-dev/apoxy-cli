package drivers

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/google/uuid"

	"github.com/apoxy-dev/apoxy-cli/pkg/clickhouse/migrations"
	"github.com/apoxy-dev/apoxy-cli/pkg/log"
	dockerutils "github.com/apoxy-dev/apoxy-cli/pkg/utils/docker"
)

const (
	dockerNetwork       = "apoxy"
	clickhouseImage     = "clickhouse/clickhouse-server:24.4.1"
	containerNamePrefix = "apoxy-clickhouse-"
)

// Driver is the interface to deploy ClickHouse server.
type Driver interface {
	// Start deploys the ClickHouse server.
	Start(ctx context.Context, orgID uuid.UUID) error

	// GetAddr returns the address of the ClickHouse server.
	GetAddr(ctx context.Context) (string, error)
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

func chWaitReady(ctx context.Context, cname string) error {
	for {
		cmd := exec.CommandContext(ctx,
			"docker", "exec",
			cname,
			"clickhouse-client",
			"--query",
			"SELECT 1",
		)
		if err := cmd.Run(); err == nil {
			return nil
		}
		log.Infof("clickhouse server is not ready, waiting...")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	panic("unreachable")
}

// Start starts a ClickHouse container if it's not already running.
func (d *dockerDriver) Start(ctx context.Context, orgID uuid.UUID) error {
	cname, found, err := dockerutils.Collect(
		ctx,
		containerNamePrefix,
		clickhouseImage,
		dockerutils.WithLabel("org.apoxy.project_id", orgID.String()),
	)
	if err != nil {
		return err
	} else if found {
		log.Infof("clickhouse server is already running: %s", cname)
		if err := migrations.Run("localhost:9000", orgID); err != nil {
			return fmt.Errorf("failed to run migrations: %w", err)
		}
		return nil
	}

	// Check for network and create if not exists.
	if err := exec.CommandContext(ctx, "docker", "network", "inspect", dockerutils.NetworkName).Run(); err != nil {
		if err := exec.CommandContext(ctx, "docker", "network", "create", dockerutils.NetworkName).Run(); err != nil {
			return fmt.Errorf("failed to create network apoxy: %w", err)
		}
	}

	log.Infof("starting clickhouse server")

	cmd := exec.CommandContext(ctx,
		"docker", "run",
		"--rm",
		"--name", cname,
		"--label", "org.apoxy.project_id="+orgID.String(),
		// Increase the number of open files limit.
		"--ulimit", "nofile=262144:262144",
		"--network", dockerutils.NetworkName,
		"-p", "8123:8123",
		"-p", "9000:9000",
		"-p", "9009:9009",
		clickhouseImage,
	)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start clickhouse server: %w", err)
	}

	if err := dockerutils.WaitForStatus(ctx, cname, "running"); err != nil {
		return fmt.Errorf("failed to start clickhouse server: %w", err)
	}
	if err := chWaitReady(ctx, cname); err != nil {
		return fmt.Errorf("failed to wait for clickhouse server: %w", err)
	}

	log.Infof("clickhouse server %q is running, running migrations...", cname)

	if err := migrations.Run("localhost:9000", orgID); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}

func (d *dockerDriver) GetAddr(ctx context.Context) (string, error) {
	cname, found, err := dockerutils.Collect(ctx, containerNamePrefix, clickhouseImage)
	if err != nil {
		return "", err
	} else if !found {
		return "", fmt.Errorf("clickhouse server not found")
	}

	return cname, nil
}

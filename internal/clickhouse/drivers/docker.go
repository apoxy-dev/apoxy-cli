package drivers

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/apoxy-dev/apoxy-cli/internal/log"
	dockerutils "github.com/apoxy-dev/apoxy-cli/internal/utils/docker"
)

const (
	dockerNetwork       = "apoxy"
	clickhouseImage     = "clickhouse/clickhouse-server:24.4.1"
	containerNamePrefix = "apoxy-clickhouse-"
)

// Driver is the interface to deploy ClickHouse server.
type Driver interface {
	// Start deploys the ClickHouse server.
	Start(ctx context.Context) error
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

// Start starts a ClickHouse container if it's not already running.
func (d *dockerDriver) Start(ctx context.Context) error {
	cname, found, err := dockerutils.Collect(ctx, containerNamePrefix, clickhouseImage)
	if err != nil {
		return err
	} else if found {
		log.Infof("clickhouse server is already running: %s", cname)
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
		"--network", dockerutils.NetworkName,
		"--name", cname,
		"-p", "8123:8123",
		"-p", "9000:9000",
		"-p", "9009:9009",
		clickhouseImage,
	)
	return cmd.Start()
}

package drivers

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/apoxy-dev/apoxy-cli/pkg/log"
)

const (
	// DefaultLogsDir is the default directory for logs
	DefaultLogsDir = "/var/log/apoxy"
	// BackplaneStdoutLogFile is the name of the backplane stdout log file
	BackplaneStdoutLogFile = "backplane.stdout.log"
	// BackplaneStderrLogFile is the name of the backplane stderr log file
	BackplaneStderrLogFile = "backplane.stderr.log"
	// BackplaneProcessName is used to identify the backplane process
	BackplaneProcessName = "backplane"
)

// SupervisorDriver implements the Driver interface for process supervision.
type SupervisorDriver struct {
	// LogsDir is the directory where logs will be written
	LogsDir string
	// cmd is the command being run
	cmd *exec.Cmd
}

// NewSupervisorDriver creates a new Supervisor driver with default configuration.
func NewSupervisorDriver() *SupervisorDriver {
	return &SupervisorDriver{
		LogsDir: DefaultLogsDir,
	}
}

// WithLogsDir sets the logs directory for the supervisor driver.
func WithLogsDir(logsDir string) func(*SupervisorDriver) {
	return func(d *SupervisorDriver) {
		d.LogsDir = logsDir
	}
}

// Start implements the Driver interface.
func (d *SupervisorDriver) Start(
	ctx context.Context,
	orgID uuid.UUID,
	proxyName string,
	opts ...Option,
) (string, error) {
	setOpts := DefaultOptions()
	for _, opt := range opts {
		opt(setOpts)
	}

	// Ensure logs directory exists
	if d.LogsDir != "" {
		if err := os.MkdirAll(d.LogsDir, 0755); err != nil {
			return "", fmt.Errorf("failed to create logs directory %s: %w", d.LogsDir, err)
		}
	}

	// Check if we already have a running process
	if d.cmd != nil && d.cmd.Process != nil {
		// Check if process is still running
		if err := d.cmd.Process.Signal(os.Signal(nil)); err == nil {
			log.Infof("Backplane process already running with PID %d", d.cmd.Process.Pid)
			return fmt.Sprintf("%s-%s", BackplaneProcessName, proxyName), nil
		}
		// Process is not running, clean up
		d.cmd = nil
	}

	// Prepare command
	d.cmd = exec.CommandContext(ctx, BackplaneProcessName)

	// Add standard arguments
	d.cmd.Args = append(d.cmd.Args, []string{
		"--project_id=" + orgID.String(),
		// Use the same name for both proxy and replica - we only have one replica.
		"--proxy=" + proxyName,
		"--replica=" + proxyName,
		"--apiserver_addr=" + net.JoinHostPort("localhost", "8443"),
		"--health_probe_port=8088",
		"--metrics_port=8089",
		"--use_envoy_contrib=true",
		"--dev=true",
	}...)

	// Add user-provided arguments
	d.cmd.Args = append(d.cmd.Args, setOpts.Args...)

	// Set up output redirection
	if d.LogsDir != "" {
		// Create or truncate log files
		stdoutPath := filepath.Join(d.LogsDir, BackplaneStdoutLogFile)
		stderrPath := filepath.Join(d.LogsDir, BackplaneStderrLogFile)

		stdoutFile, err := os.Create(stdoutPath)
		if err != nil {
			return "", fmt.Errorf("failed to create stdout log file %s: %w", stdoutPath, err)
		}

		stderrFile, err := os.Create(stderrPath)
		if err != nil {
			stdoutFile.Close()
			return "", fmt.Errorf("failed to create stderr log file %s: %w", stderrPath, err)
		}

		d.cmd.Stdout = stdoutFile
		d.cmd.Stderr = stderrFile

		log.Infof("Backplane logs will be written to %s and %s", stdoutPath, stderrPath)
	} else {
		// Use os.Stdout and os.Stderr directly
		d.cmd.Stdout = os.Stdout
		d.cmd.Stderr = os.Stderr
		log.Infof("Backplane logs will be written to stdout and stderr")
	}

	log.Infof("Starting backplane process with command: %v", d.cmd.Args)

	// Start the process
	if err := d.cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start backplane process: %w", err)
	}

	log.Infof("Started backplane process with PID %d", d.cmd.Process.Pid)

	// Return a unique identifier for this process
	return fmt.Sprintf("%s-%s", BackplaneProcessName, proxyName), nil
}

// Stop implements the Driver interface.
func (d *SupervisorDriver) Stop(orgID uuid.UUID, proxyName string) {
	if d.cmd == nil || d.cmd.Process == nil {
		log.Infof("No backplane process to stop")
		return
	}

	log.Infof("Stopping backplane process with PID %d", d.cmd.Process.Pid)

	// Create a context with timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try to terminate gracefully first
	if err := d.cmd.Process.Signal(os.Interrupt); err != nil {
		log.Errorf("Failed to send interrupt signal to backplane process: %v", err)
		// Try to kill forcefully
		if err := d.cmd.Process.Kill(); err != nil {
			log.Errorf("Failed to kill backplane process: %v", err)
		}
	}

	// Wait for process to exit or timeout
	done := make(chan error, 1)
	go func() {
		done <- d.cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			log.Errorf("Backplane process exited with error: %v", err)
		} else {
			log.Infof("Backplane process exited successfully")
		}
	case <-ctx.Done():
		log.Errorf("Timeout waiting for backplane process to exit, forcing kill")
		if err := d.cmd.Process.Kill(); err != nil {
			log.Errorf("Failed to kill backplane process: %v", err)
		}
	}

	// Clean up
	d.cmd = nil
}

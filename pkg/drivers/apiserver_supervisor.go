package drivers

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/apoxy-dev/apoxy/pkg/log"
)

const (
	// APIServerStdoutLogFile is the name of the apiserver stdout log file
	APIServerStdoutLogFile = "apiserver.stdout.log"
	// APIServerStderrLogFile is the name of the apiserver stderr log file
	APIServerStderrLogFile = "apiserver.stderr.log"
	// APIServerProcessName is used to identify the apiserver process
	APIServerProcessName = "apiserver"
)

// APIServerSupervisorDriver implements the Driver interface for process supervision.
type APIServerSupervisorDriver struct {
	// LogsDir is the directory where logs will be written
	LogsDir string
	// cmd is the command being run
	cmd *exec.Cmd
}

// NewAPIServerSupervisorDriver creates a new Supervisor driver with default configuration.
func NewAPIServerSupervisorDriver() *APIServerSupervisorDriver {
	return &APIServerSupervisorDriver{
		LogsDir: DefaultLogsDir,
	}
}

// Start implements the Driver interface.
func (d *APIServerSupervisorDriver) Start(
	ctx context.Context,
	orgID uuid.UUID,
	serviceName string,
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
			log.Infof("API server process already running with PID %d", d.cmd.Process.Pid)
			return fmt.Sprintf("%s-%s", APIServerProcessName, serviceName), nil
		}
		// Process is not running, clean up
		d.cmd = nil
	}

	// Prepare command
	d.cmd = exec.CommandContext(ctx, APIServerProcessName)

	// Add standard arguments
	d.cmd.Args = append(d.cmd.Args, []string{
		"--dev=true",
	}...)

	// Add user-provided arguments
	d.cmd.Args = append(d.cmd.Args, setOpts.Args...)

	// Set up output redirection
	if d.LogsDir != "" {
		// Create or truncate log files
		stdoutPath := filepath.Join(d.LogsDir, APIServerStdoutLogFile)
		stderrPath := filepath.Join(d.LogsDir, APIServerStderrLogFile)

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

		log.Infof("API server logs will be written to %s and %s", stdoutPath, stderrPath)
	} else {
		// Use os.Stdout and os.Stderr directly
		d.cmd.Stdout = os.Stdout
		d.cmd.Stderr = os.Stderr
		log.Infof("API server logs will be written to stdout and stderr")
	}

	log.Infof("Starting API server process with command: %v", d.cmd.Args)

	// Start the process
	if err := d.cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start API server process: %w", err)
	}

	log.Infof("Started API server process with PID %d", d.cmd.Process.Pid)

	// Wait for the API server to be healthy
	if err := healthCheckAPIServer(); err != nil {
		return "", err
	}

	// Return a unique identifier for this process
	return fmt.Sprintf("%s-%s", APIServerProcessName, serviceName), nil
}

// Stop implements the Driver interface.
func (d *APIServerSupervisorDriver) Stop(orgID uuid.UUID, serviceName string) {
	if d.cmd == nil || d.cmd.Process == nil {
		log.Infof("No API server process to stop")
		return
	}

	log.Infof("Stopping API server process with PID %d", d.cmd.Process.Pid)

	// Create a context with timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try to terminate gracefully first
	if err := d.cmd.Process.Signal(os.Interrupt); err != nil {
		log.Errorf("Failed to send interrupt signal to API server process: %v", err)
		// Try to kill forcefully
		if err := d.cmd.Process.Kill(); err != nil {
			log.Errorf("Failed to kill API server process: %v", err)
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
			log.Errorf("API server process exited with error: %v", err)
		} else {
			log.Infof("API server process exited successfully")
		}
	case <-ctx.Done():
		log.Errorf("Timeout waiting for API server process to exit, forcing kill")
		if err := d.cmd.Process.Kill(); err != nil {
			log.Errorf("Failed to kill API server process: %v", err)
		}
	}

	// Clean up
	d.cmd = nil
}

// GetAddr implements the Driver interface.
func (d *APIServerSupervisorDriver) GetAddr(ctx context.Context) (string, error) {
	return "localhost", nil
}

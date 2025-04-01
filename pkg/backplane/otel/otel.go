// Package otel provides functionality for managing OpenTelemetry collector processes.
package otel

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/apoxy-dev/apoxy-cli/pkg/log"
)

const (
	// DefaultCollectorBinary is the default path to the otel-collector binary
	DefaultCollectorBinary = "run/bin/otel-collector"

	// DefaultLogsDir is the default directory for logs
	DefaultLogsDir = "/var/log/apoxy"

	// CollectorStdoutLogFile is the name of the collector stdout log file
	CollectorStdoutLogFile = "otel-collector.stdout.log"

	// CollectorStderrLogFile is the name of the collector stderr log file
	CollectorStderrLogFile = "otel-collector.stderr.log"

	// DefaultConfigPath is the default path to the otel-collector config file
	DefaultConfigPath = "/etc/otelcol/config.yaml"

	// DefaultConfigContent is the default content for the otel-collector config file
	DefaultConfigContent = `receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

exporters:
  debug:

extensions:
  zpages:
    endpoint: 0.0.0.0:55679

service:
  extensions:
  - zpages
  pipelines:
    traces:
      receivers:
      - otlp
      exporters:
      - debug
`
)

// Option configures a Collector.
type Option func(*Collector)

// WithCollectorBinary sets the path to the otel-collector binary.
func WithCollectorBinary(path string) Option {
	return func(c *Collector) {
		c.CollectorBinary = path
	}
}

// WithLogsDir sets the directory where logs will be written.
func WithLogsDir(path string) Option {
	return func(c *Collector) {
		c.LogsDir = path
	}
}

// WithArgs sets additional arguments to pass to the otel-collector.
func WithArgs(args ...string) Option {
	return func(c *Collector) {
		c.Args = append(c.Args, args...)
	}
}

// WithConfig sets the configuration file path for the otel-collector.
func WithConfig(configPath string) Option {
	return func(c *Collector) {
		c.ConfigPath = configPath
	}
}

// Collector manages the OpenTelemetry collector process.
type Collector struct {
	// CollectorBinary is the path to the otel-collector binary
	CollectorBinary string
	// LogsDir is the directory where logs will be written
	LogsDir string
	// ConfigPath is the path to the otel-collector config file
	ConfigPath string
	// Args are additional arguments to pass to the otel-collector
	Args []string

	cmd    *exec.Cmd
	stopCh chan struct{}
	mu     sync.RWMutex
	status CollectorStatus
}

// CollectorStatus represents the status of the otel-collector process.
type CollectorStatus struct {
	StartedAt time.Time
	Running   bool
	ProcState *os.ProcessState
}

// Status returns the current status of the otel-collector process.
func (c *Collector) Status() CollectorStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

// setOptions applies the provided options to the Collector.
func (c *Collector) setOptions(opts ...Option) {
	for _, opt := range opts {
		opt(c)
	}

	// Set defaults if not provided
	if c.CollectorBinary == "" {
		// Use the default binary path relative to the current working directory
		cwd, err := os.Getwd()
		if err == nil {
			c.CollectorBinary = filepath.Join(cwd, DefaultCollectorBinary)
		} else {
			c.CollectorBinary = DefaultCollectorBinary
		}
	}

	if c.LogsDir == "" {
		c.LogsDir = DefaultLogsDir
	}
}

// Start starts the otel-collector process.
func (c *Collector) Start(ctx context.Context, opts ...Option) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Apply options
	c.setOptions(opts...)

	// Check if already running
	if c.cmd != nil && c.cmd.Process != nil {
		// Check if process is still running
		if err := c.cmd.Process.Signal(os.Signal(nil)); err == nil {
			log.Infof("OpenTelemetry collector already running with PID %d", c.cmd.Process.Pid)
			return nil
		}
		// Process is not running, clean up
		c.cmd = nil
	}

	// Ensure logs directory exists
	if c.LogsDir != "" {
		if err := os.MkdirAll(c.LogsDir, 0755); err != nil {
			return fmt.Errorf("failed to create logs directory %s: %w", c.LogsDir, err)
		}
	}

	// Check if default config file exists, if not, create it
	if c.ConfigPath == "" {
		// Check if default config file exists
		if _, err := os.Stat(DefaultConfigPath); os.IsNotExist(err) {
			// Create directory if it doesn't exist
			if err := os.MkdirAll(filepath.Dir(DefaultConfigPath), 0755); err != nil {
				return fmt.Errorf("failed to create config directory %s: %w", filepath.Dir(DefaultConfigPath), err)
			}

			// Create default config file
			if err := os.WriteFile(DefaultConfigPath, []byte(DefaultConfigContent), 0644); err != nil {
				return fmt.Errorf("failed to create default config file %s: %w", DefaultConfigPath, err)
			}
			log.Infof("Created default OpenTelemetry collector config at %s", DefaultConfigPath)
		} else if err != nil {
			return fmt.Errorf("failed to check if config file exists %s: %w", DefaultConfigPath, err)
		} else {
			log.Infof("Using existing OpenTelemetry collector config at %s", DefaultConfigPath)
		}

		// Use default config file
		c.ConfigPath = DefaultConfigPath
	}

	// Prepare command
	c.cmd = exec.CommandContext(ctx, c.CollectorBinary)

	// Add standard arguments
	args := []string{}

	// Add config file if specified
	if c.ConfigPath != "" {
		args = append(args, "--config", c.ConfigPath)
	}

	// Add user-provided arguments
	args = append(args, c.Args...)
	c.cmd.Args = append(c.cmd.Args, args...)

	// Set up output redirection
	if c.LogsDir != "" {
		// Create or truncate log files
		stdoutPath := filepath.Join(c.LogsDir, CollectorStdoutLogFile)
		stderrPath := filepath.Join(c.LogsDir, CollectorStderrLogFile)

		stdoutFile, err := os.Create(stdoutPath)
		if err != nil {
			return fmt.Errorf("failed to create stdout log file %s: %w", stdoutPath, err)
		}

		stderrFile, err := os.Create(stderrPath)
		if err != nil {
			stdoutFile.Close()
			return fmt.Errorf("failed to create stderr log file %s: %w", stderrPath, err)
		}

		c.cmd.Stdout = stdoutFile
		c.cmd.Stderr = stderrFile

		log.Infof("OpenTelemetry collector logs will be written to %s and %s", stdoutPath, stderrPath)
	} else {
		// Use os.Stdout and os.Stderr directly
		c.cmd.Stdout = os.Stdout
		c.cmd.Stderr = os.Stderr
		log.Infof("OpenTelemetry collector logs will be written to stdout and stderr")
	}

	log.Infof("Starting OpenTelemetry collector process with command: %v", c.cmd.Args)

	// Start the process
	if err := c.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start OpenTelemetry collector process: %w", err)
	}

	log.Infof("Started OpenTelemetry collector process with PID %d", c.cmd.Process.Pid)

	// Update status
	c.status = CollectorStatus{
		StartedAt: time.Now(),
		Running:   true,
	}

	// Create stop channel
	c.stopCh = make(chan struct{})

	// Monitor process in background
	go func() {
		err := c.cmd.Wait()

		c.mu.Lock()
		defer c.mu.Unlock()

		c.status.Running = false
		c.status.ProcState = c.cmd.ProcessState

		if err != nil {
			log.Errorf("OpenTelemetry collector process exited with error: %v", err)
		} else {
			log.Infof("OpenTelemetry collector process exited successfully")
		}

		// Signal that the process has stopped if that hasn't already been signalled.
		select {
		case <-c.stopCh:
		default:
			close(c.stopCh)
		}
	}()

	return nil
}

// Stop stops the otel-collector process.
func (c *Collector) Stop(ctx context.Context) error {
	c.mu.Lock()

	// Check if already stopped
	if c.cmd == nil || c.cmd.Process == nil {
		c.mu.Unlock()
		log.Infof("No OpenTelemetry collector process to stop")
		return nil
	}

	stopCh := c.stopCh
	pid := c.cmd.Process.Pid
	c.mu.Unlock()

	log.Infof("Stopping OpenTelemetry collector process with PID %d", pid)

	// Try to terminate gracefully first
	if err := c.cmd.Process.Signal(os.Interrupt); err != nil {
		log.Errorf("Failed to send interrupt signal to OpenTelemetry collector process: %v", err)
		// Try to kill forcefully
		if err := c.cmd.Process.Kill(); err != nil {
			return fmt.Errorf("failed to kill OpenTelemetry collector process: %v", err)
		}
	}

	// Wait for process to exit or timeout
	select {
	case <-stopCh:
		log.Infof("OpenTelemetry collector process stopped")
	case <-ctx.Done():
		log.Errorf("Timeout waiting for OpenTelemetry collector process to exit, forcing kill")
		c.mu.Lock()
		if c.cmd != nil && c.cmd.Process != nil {
			if err := c.cmd.Process.Kill(); err != nil {
				c.mu.Unlock()
				return fmt.Errorf("failed to kill OpenTelemetry collector process: %v", err)
			}
		}
		c.mu.Unlock()
	}

	return nil
}

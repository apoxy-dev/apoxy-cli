package envoy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/shirou/gopsutil/process"

	"github.com/apoxy-dev/apoxy-cli/config"
	"github.com/apoxy-dev/apoxy-cli/pkg/backplane/logs"
	"github.com/apoxy-dev/apoxy-cli/pkg/backplane/otel"
	"github.com/apoxy-dev/apoxy-cli/pkg/log"
)

const (
	githubURL = "github.com/envoyproxy/envoy/releases/download"

	accessLogsPath = "/var/log/accesslogs"
	tapsPath       = "/var/log/taps"

	defaultDrainTimeoutSeconds = 30
)

var (
	goArchToPlatform = map[string]string{
		"amd64": "x86_64",
		"arm64": "aarch_64",
	}
)

// Option configures a Runtime.
type Option func(*Runtime)

// WithBootstrapConfigYAML sets the Envoy bootstrap config YAML.
func WithBootstrapConfigYAML(yaml string) Option {
	return func(r *Runtime) {
		r.BootstrapConfigYAML = yaml
	}
}

// WithCluster sets the Envoy cluster name.
// If this is not set, a random cluster name is used.
// The cluster name is used in the Envoy bootstrap config.
func WithCluster(cluster string) Option {
	return func(r *Runtime) {
		r.Cluster = cluster
	}
}

// WithArgs sets additional arguments to pass to Envoy.
// The arguments are appended to the default arguments.
func WithArgs(args ...string) Option {
	return func(r *Runtime) {
		r.Args = append(r.Args, args...)
	}
}

// WithRelease sets the Envoy release to use.
// If this is not set, the latest release is used.
func WithRelease(release ReleaseDownloader) Option {
	return func(r *Runtime) {
		r.Release = release
	}
}

// WithLogsCollector sets the logs collector.
func WithLogsCollector(c logs.LogsCollector) Option {
	return func(r *Runtime) {
		r.logs = c
	}
}

// WithGoPluginDir sets the directory to load Go plugins from.
func WithGoPluginDir(dir string) Option {
	return func(r *Runtime) {
		r.goPluginDir = dir
	}
}

// WithAdminHost sets the host for the Envoy admin interface.
func WithAdminHost(host string) Option {
	return func(r *Runtime) {
		r.adminHost = host
	}
}

// If this is not set, the default timeout is used (30 seconds).
func WithDrainTimeout(timeout *time.Duration) Option {
	return func(r *Runtime) {
		r.drainTimeout = timeout
	}
}

func WithOtelCollector() Option {
	return func(r *Runtime) {
		r.otelCollector = &otel.Collector{}
	}
}

// WithOtelCollector sets the OpenTelemetry collector.
func WithOtelCollector(c *otel.Collector) Option {
	return func(r *Runtime) {
		r.otelCollector = c
	}
}

type Runtime struct {
	EnvoyPath           string
	BootstrapConfigYAML string
	Release             ReleaseDownloader
	Cluster             string
	// Args are additional arguments to pass to Envoy.
	Args []string

	stopCh        chan struct{}
	cmd           *exec.Cmd
	logs          logs.LogsCollector
	otelCollector *otel.Collector
	goPluginDir   string
	adminHost     string
	drainTimeout  *time.Duration

	mu     sync.RWMutex
	status RuntimeStatus
}

func (r *Runtime) setOptions(opts ...Option) {
	for _, opt := range opts {
		opt(r)
	}
	if r.Release == nil {
		r.Release = &GitHubRelease{}
	}
	if r.Cluster == "" {
		r.Cluster = uuid.New().String()
	}
	if r.drainTimeout == nil {
		drainTimeout := defaultDrainTimeoutSeconds * time.Second
		r.drainTimeout = &drainTimeout
	}
}

func (r *Runtime) run(ctx context.Context) error {
	id := uuid.New().String()
	configYAML := fmt.Sprintf(`node: { id: "%s", cluster: "%s" }`, id, r.Cluster)
	log.Infof("envoy YAML config: %s", configYAML)

	// Start OpenTelemetry collector if configured
	if r.otelCollector != nil {
		log.Infof("Starting OpenTelemetry collector before Envoy")
		if err := r.otelCollector.Start(ctx); err != nil {
			return fmt.Errorf("failed to start OpenTelemetry collector: %w", err)
		}
	}

	args := []string{
		"--config-yaml", configYAML,
	}

	if r.BootstrapConfigYAML != "" {
		f, err := os.CreateTemp("", "bootstrap-*.yaml")
		if err != nil {
			return fmt.Errorf("failed to create bootstrap config file: %w", err)
		}
		if _, err := f.WriteString(r.BootstrapConfigYAML); err != nil {
			return fmt.Errorf("failed to write bootstrap config file: %w", err)
		}
		args = append(args, "-c", f.Name())
	}

	rCtx, cancel := context.WithCancelCause(ctx)
	if r.logs != nil {
		go func() {
			err := r.logs.CollectAccessLogs(ctx, accessLogsPath)
			if err != nil {
				log.Errorf("failed to collect access logs: %v", err)
				cancel(fmt.Errorf("access logs collector failed: %v", err))
			}
		}()
		go func() {
			err := r.logs.CollectTaps(ctx, tapsPath)
			if err != nil {
				cancel(fmt.Errorf("taps collector failed: %v", err))
				log.Errorf("failed to collect taps: %v", err)
			}
		}()
	}

	runDir := os.TempDir()
	if r.goPluginDir != "" {
		log.Infof("linking go plugin directory %s to runDir %s", r.goPluginDir, runDir)
		// Link the Go plugin directory to the run directory.
		_, err := os.Lstat(filepath.Join(runDir, "go"))
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to check if go plugin directory symlink exists: %w", err)
		} else if err == nil {
			if err := os.Remove(filepath.Join(runDir, "go")); err != nil {
				return fmt.Errorf("failed to remove existing go plugin directory symlink: %w", err)
			}
		}

		if err := os.Symlink(r.goPluginDir, filepath.Join(runDir, "go")); err != nil {
			return fmt.Errorf("failed to symlink go plugin directory: %w", err)
		}
	}

	args = append(args, "--drain-time-s", strconv.Itoa(int(r.drainTimeout.Seconds())))
	args = append(args, r.Args...)
	r.cmd = exec.CommandContext(rCtx, r.envoyPath(), args...)
	r.cmd.Dir = runDir

	if r.envoyLogsDir != "" {
		// Create logs directory if it doesn't exist
		if err := os.MkdirAll(r.envoyLogsDir, 0755); err != nil {
			return fmt.Errorf("failed to create logs directory: %w", err)
		}

		// Create a temporary file for stdout and stderr
		// We'll rename these files after the process starts and we have the PID
		tmpStdoutFile, err := os.CreateTemp(r.envoyLogsDir, "envoy.stdout.*")
		if err != nil {
			return fmt.Errorf("failed to create temporary stdout file: %w", err)
		}
		tmpStderrFile, err := os.CreateTemp(r.envoyLogsDir, "envoy.stderr.*")
		if err != nil {
			tmpStdoutFile.Close()
			os.Remove(tmpStdoutFile.Name())
			return fmt.Errorf("failed to create temporary stderr file: %w", err)
		}

		defer tmpStdoutFile.Close()
		defer tmpStderrFile.Close()
		r.cmd.Stdout = io.MultiWriter(os.Stdout, tmpStdoutFile)
		r.cmd.Stderr = io.MultiWriter(os.Stderr, tmpStderrFile)

		if err := r.cmd.Start(); err != nil {
			os.Remove(tmpStdoutFile.Name())
			os.Remove(tmpStderrFile.Name())
			return fmt.Errorf("failed to start envoy: %w", err)
		}

		pid := r.cmd.Process.Pid
		log.Infof("envoy started with PID %d", pid)
		stdoutLogPath := filepath.Join(r.envoyLogsDir, fmt.Sprintf("envoy.%d.stdout.log", pid))
		stderrLogPath := filepath.Join(r.envoyLogsDir, fmt.Sprintf("envoy.%d.stderr.log", pid))

		// Rename the temporary files to their final names
		if err := os.Rename(tmpStdoutFile.Name(), stdoutLogPath); err != nil {
			log.Errorf("failed to rename stdout log file: %v", err)
			os.Remove(tmpStdoutFile.Name())
		}
		if err := os.Rename(tmpStderrFile.Name(), stderrLogPath); err != nil {
			log.Errorf("failed to rename stderr log file: %v", err)
			os.Remove(tmpStderrFile.Name())
		}
	} else {
		// Default behavior: pipe to os.Stdout and os.Stderr
		r.cmd.Stdout = os.Stdout
		r.cmd.Stderr = os.Stderr
		if err := r.cmd.Start(); err != nil {
			return fmt.Errorf("failed to start envoy: %w", err)
		}
	}

	r.mu.Lock()
	p, err := process.NewProcess(int32(r.cmd.Process.Pid))
	if err != nil {
		r.mu.Unlock()
		return fmt.Errorf("failed to find envoy process: %w", err)
	}
	ctime, err := p.CreateTimeWithContext(rCtx)
	if err != nil {
		r.mu.Unlock()
		return fmt.Errorf("failed to get envoy process create time: %w", err)
	}
	// Convert from milliseconds to seconds.
	r.status.StartedAt = time.Unix(0, ctime*int64(time.Millisecond)).UTC()
	r.status.Running = true
	r.status.Starting = false
	r.mu.Unlock()

	// Restart envoy if it exits.
	if err := r.cmd.Wait(); err != nil {
		return fmt.Errorf("envoy exited with error: %w", err)
	}

	r.mu.Lock()
	r.status.Running = false
	r.status.ProcState = r.cmd.ProcessState
	r.mu.Unlock()

	return nil
}

// envoyPath returns the path to the Envoy binary. If EnvoyPath is set, it will
// be used. Otherwise, the binary will be downloaded and cached in the user's
// home directory.
func (r *Runtime) envoyPath() string {
	if r.EnvoyPath != "" {
		return r.EnvoyPath
	}
	return config.ApoxyDir() + "/envoy/envoy"
}

// vendorEnvoyIfNotExists vendors the Envoy binary for the release if it does
// not exist.
func (r *Runtime) vendorEnvoyIfNotExists(ctx context.Context) error {
	if _, err := os.Stat(r.envoyPath()); err == nil {
		return nil
	}

	// Download the Envoy binary for the release.
	bin, err := r.Release.DownloadBinary(ctx)
	if err != nil {
		return fmt.Errorf("failed to download envoy: %w", err)
	}
	defer bin.Close()

	// Extract the Envoy binary.
	if err := os.MkdirAll(filepath.Dir(r.envoyPath()), 0755); err != nil {
		return fmt.Errorf("failed to create envoy directory: %w", err)
	}
	w, err := os.OpenFile(r.envoyPath(), os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		return fmt.Errorf("failed to open envoy: %w", err)
	}
	defer w.Close()
	if _, err := io.Copy(w, bin); err != nil {
		return fmt.Errorf("failed to copy envoy: %w", err)
	}
	if err := os.Chmod(r.envoyPath(), 0755); err != nil {
		return fmt.Errorf("failed to chmod envoy: %w", err)
	}

	return nil
}

// FatalError is an error that should cause the runtime to exit.
type FatalError struct {
	Err error
}

// Error implements the error interface.
func (e FatalError) Error() string {
	return e.Err.Error()
}

// Start starts the Envoy binary.
func (r *Runtime) Start(ctx context.Context, opts ...Option) error {
	status := r.RuntimeStatus()
	if status.Starting || status.Running {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.Starting = true

	r.setOptions(opts...)

	log.Infof("preparing envoy %s", r.Release)

	if err := r.vendorEnvoyIfNotExists(ctx); err != nil {
		return FatalError{Err: fmt.Errorf("failed to vendor envoy: %w", err)}
	}

	r.stopCh = make(chan struct{})
	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Infof("context done")
			case <-r.stopCh:
				log.Infof("envoy stopped")
				return
			default:
			}

			if err := r.run(ctx); err != nil {
				log.Errorf("envoy exited with error: %v", err)
			}

			select {
			case <-ctx.Done():
				log.Infof("context done")
			case <-r.stopCh:
				log.Infof("envoy stopped")
				return
			default: // Restart envoy.
			}
		}
	}()

	return nil
}

// postEnvoyAdminAPI sends a POST request to the Envoy admin API.
func (r *Runtime) postEnvoyAdminAPI(path string) error {
	if r.cmd == nil {
		return errors.New("envoy not running")
	}
	if r.adminHost == "" {
		return errors.New("envoy admin host not set")
	}
	resp, err := http.Post("http://"+r.adminHost+"/"+path, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response status: %s", resp.Status)
	}
	return nil
}

// getTotalConnections retrieves the total number of open connections from Envoy's server.total_connections stat.
func (r *Runtime) getTotalConnections() (*int, error) {
	resp, err := http.Get(fmt.Sprintf("http://%s//stats?filter=^server\\.total_connections$&format=json",
		r.adminHost))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	// Define struct to decode JSON response into; expecting a single stat in the response in the format:
	// {"stats":[{"name":"server.total_connections","value":123}]}
	var jsonData *struct {
		Stats []struct {
			Name  string `json:"name"`
			Value int    `json:"value"`
		} `json:"stats"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jsonData); err != nil {
		return nil, err
	}

	if len(jsonData.Stats) == 0 {
		return nil, fmt.Errorf("no stats found")
	}
	c := jsonData.Stats[0].Value

	log.Infof("total connections: %d", c)

	return &c, nil
}

// Shutdown gracefully drains connections and shuts down the Envoy process.
func (r *Runtime) Shutdown(ctx context.Context) error {
	r.mu.Lock()
	if r.stopCh == nil {
		r.mu.Unlock()
		return nil
	}
	stopCh := r.stopCh
	r.stopCh = nil
	r.mu.Unlock()

	close(stopCh)

	if r.cmd == nil || r.cmd.Process == nil {
		return nil
	}

	// Use sync.OnceValue to ensure the shutdown process only executes once
	stopOnce := sync.OnceValue(func() error {
		log.Infof("Shutting down Envoy with drain timeout %s", *r.drainTimeout)

		// First fail health checks to stop receiving new traffic
		if err := r.postEnvoyAdminAPI("healthcheck/fail"); err != nil {
			log.Warnf("Failed to fail active health checks: %v", err)
			// Continue with shutdown even if this fails
		}

		drainCtx, cancel := context.WithTimeout(ctx, *r.drainTimeout)
		defer cancel()

		// Initiate graceful drain but tell Envoy not to exit automatically
		if err := r.postEnvoyAdminAPI("drain_listeners?graceful&skip_exit"); err != nil {
			log.Warnf("Failed to initiate graceful drain: %v", err)
			// Continue with shutdown even if drain fails
		}

		// Wait for connections to drain
		drainStart := time.Now()
		for {
			if time.Since(drainStart) > *r.drainTimeout {
				log.Warnf("Drain timeout exceeded, proceeding with shutdown")
				break
			}

			conns, err := r.getTotalConnections()
			if err != nil {
				log.Warnf("Failed to get connection count: %v", err)
				break
			}

			if conns == nil || *conns == 0 {
				log.Infof("All connections drained")
				break
			}

			log.Infof("Waiting for %d connections to drain", *conns)
			select {
			case <-drainCtx.Done():
				log.Warnf("Drain context canceled, proceeding with shutdown")
				break
			case <-time.After(1 * time.Second):
				// Continue waiting
			}
		}

		// Shutdown Envoy process
		log.Infof("Shutting down Envoy process")
		if err := r.cmd.Process.Signal(os.Interrupt); err != nil {
			log.Warnf("Failed to send interrupt signal to Envoy: %v", err)
			if err := r.cmd.Process.Kill(); err != nil {
				return fmt.Errorf("failed to kill Envoy process: %w", err)
			}
		}

		// Wait for process to exit
		if err := r.cmd.Wait(); err != nil {
			log.Warnf("Envoy process exited with error: %v", err)
		}

		// Shutdown OpenTelemetry collector if it was started
		if r.otelCollector != nil {
			log.Infof("Shutting down OpenTelemetry collector")
			shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if err := r.otelCollector.Stop(shutdownCtx); err != nil {
				log.Warnf("Failed to stop OpenTelemetry collector: %v", err)
			}
		}

		return nil
	})

	return stopOnce()
}

type RuntimeStatus struct {
	StartedAt time.Time
	Starting  bool
	Running   bool
	ProcState *os.ProcessState
}

// RuntimeStatus returns the status of the Envoy process.
func (r *Runtime) RuntimeStatus() RuntimeStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status
}

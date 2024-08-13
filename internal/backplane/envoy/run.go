package envoy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/google/go-github/v61/github"
	"github.com/google/uuid"
	"github.com/shirou/gopsutil/process"

	"github.com/apoxy-dev/apoxy-cli/config"
	"github.com/apoxy-dev/apoxy-cli/internal/backplane/logs"
	"github.com/apoxy-dev/apoxy-cli/internal/log"
)

const (
	githubURL = "github.com/envoyproxy/envoy/releases/download"

	accessLogsPath = "/var/log/accesslogs"
	tapsPath       = "/var/log/taps"
)

var (
	goArchToPlatform = map[string]string{
		"amd64": "x86_64",
		"arm64": "aarch_64",
	}
)

type Release struct {
	Version string
	Sha     string
}

func (r *Release) String() string {
	if r.Sha == "" {
		return r.Version
	}
	return fmt.Sprintf("%s@sha256:%s", r.Version, r.Sha)
}

func (r *Release) DownloadBinaryFromGitHub(ctx context.Context) (io.ReadCloser, error) {
	release := r.String()
	if release == "" {
		c := github.NewClient(nil)
		latest, _, err := c.Repositories.GetLatestRelease(ctx, "envoyproxy", "envoy")
		if err != nil {
			return nil, fmt.Errorf("failed to get latest envoy release: %w", err)
		}
		r.Version = latest.GetTagName()
	}
	downloadURL := filepath.Join(
		githubURL,
		r.Version,
		fmt.Sprintf("envoy-%s-%s-%s", r.Version[1:], runtime.GOOS, goArchToPlatform[runtime.GOARCH]),
	)

	log.Infof("downloading envoy %s from https://%s", r, downloadURL)

	resp, err := http.Get("https://" + downloadURL)
	if err != nil {
		return nil, fmt.Errorf("failed to download envoy: %w", err)
	}
	return resp.Body, nil
}

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
func WithRelease(release *Release) Option {
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

// Runtime vendors the Envoy binary and runs it.
type Runtime struct {
	EnvoyPath           string
	BootstrapConfigYAML string
	Release             *Release
	Cluster             string
	// Args are additional arguments to pass to Envoy.
	Args []string

	exitCh      chan struct{}
	cmd         *exec.Cmd
	logs        logs.LogsCollector
	goPluginDir string

	mu     sync.RWMutex
	status RuntimeStatus
}

func (r *Runtime) setOptions(opts ...Option) {
	for _, opt := range opts {
		opt(r)
	}
	if r.Release == nil {
		r.Release = &Release{}
	}
	if r.Cluster == "" {
		r.Cluster = uuid.New().String()
	}
}

func (r *Runtime) run(ctx context.Context) error {
	id := uuid.New().String()
	configYAML := fmt.Sprintf(`node: { id: "%s", cluster: "%s" }`, id, r.Cluster)
	log.Infof("envoy YAML config: %s", configYAML)

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
		// Link the Go plugin directory to the run directory.
		if err := os.Symlink(r.goPluginDir, filepath.Join(runDir, "go")); err != nil {
			return fmt.Errorf("failed to symlink go plugin directory: %w", err)
		}
	}

	args = append(args, r.Args...)
	r.cmd = exec.CommandContext(rCtx, r.envoyPath(), args...)
	r.cmd.Dir = runDir
	r.cmd.Stdout = os.Stdout
	r.cmd.Stderr = os.Stderr

	if err := r.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start envoy: %w", err)
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
	bin, err := r.Release.DownloadBinaryFromGitHub(ctx)
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
	if r.cmd != nil {
		return errors.New("envoy already running")
	}

	r.setOptions(opts...)

	log.Infof("running envoy %s", r.Release)

	if err := r.vendorEnvoyIfNotExists(ctx); err != nil {
		return FatalError{Err: fmt.Errorf("failed to vendor envoy: %w", err)}
	}

	r.exitCh = make(chan struct{})
	go func() {
		defer r.Stop()
		for {
			select {
			case <-ctx.Done():
				log.Infof("context done")
			default:
			}

			if err := r.run(ctx); err != nil {
				log.Errorf("envoy exited with error: %v", err)
			}

			select {
			case <-ctx.Done():
				log.Infof("context done")
			case <-r.exitCh:
				log.Infof("envoy stopped")
			default: // Restart envoy.
			}
		}
	}()

	return nil
}

// Stop stops the Envoy process.
func (r *Runtime) Stop() error {
	if r.cmd == nil {
		return nil
	}
	stopOnce := sync.OnceValue(func() error {
		close(r.exitCh)
		return r.cmd.Process.Kill()
	})
	return stopOnce()
}

type RuntimeStatus struct {
	StartedAt time.Time
	Running   bool
	ProcState *os.ProcessState
}

// RuntimeStatus returns the status of the Envoy process.
func (r *Runtime) RuntimeStatus() RuntimeStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status
}

package config

import (
	"fmt"
	"io/ioutil"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
	"k8s.io/klog/v2"

	"github.com/apoxy-dev/apoxy-cli/rest"
)

var (
	ConfigFile    string
	Verbose       bool
	DefaultConfig = &Config{
		APIKey:       "",
		Verbose:      false,
		APIBaseURL:   "https://api.apoxy.dev",
		DashboardURL: "https://dashboard.apoxy.dev",
	}
)

type Config struct {
	// The API key to use for authentication.
	APIKey string `yaml:"api_key,omitempty"`
	// The project ID to use for authentication.
	ProjectID uuid.UUID `yaml:"project_id,omitempty"`
	// Whether to enable verbose logging.
	Verbose bool `yaml:"verbose,omitempty"`
	// The base URL for API requests.
	APIBaseURL string `yaml:"api_base_url,omitempty"`
	// The host header to set for API requests.
	APIBaseHost string `yaml:"api_base_host,omitempty"`
	// The URL for the dashboard UI.
	DashboardURL string `yaml:"dashboard_url,omitempty"`
}

// ApoxyDir returns the path to the Apoxy configuration directory.
func ApoxyDir() string {
	return filepath.Join(os.Getenv("HOME"), ".apoxy")
}

func getDefaultConfigPath() string {
	return filepath.Join(ApoxyDir(), "config.yaml")
}

func Load() (*Config, error) {
	if ConfigFile == "" {
		ConfigFile = getDefaultConfigPath()
	}
	if _, err := os.Stat(ConfigFile); os.IsNotExist(err) {
		return DefaultConfig, nil
	}
	yamlFile, err := ioutil.ReadFile(ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("error reading YAML file: %v", err)
	}
	cfg := new(Config)
	if err := yaml.Unmarshal(yamlFile, cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %v", err)
	}

	if Verbose || cfg.Verbose {
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
		slog.SetDefault(logger)
		klog.SetSlogLogger(logger)
		slog.Debug("Verbose logging enabled")
	} else {
		klog.SetOutput(ioutil.Discard)
		klog.LogToStderr(false)
	}

	return cfg, nil
}

func ensureDirExists(filePath string) error {
	dir := filepath.Dir(filePath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		// Create the directory if it doesn't exist
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return fmt.Errorf("failed to create directory: %v", err)
		}
	}
	return nil
}

func Store(cfg *Config) error {
	yamlFile, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %v", err)
	}
	if ConfigFile == "" {
		ConfigFile = getDefaultConfigPath()
	}
	if err := ensureDirExists(ConfigFile); err != nil {
		return fmt.Errorf("failed to ensure directory exists: %v", err)
	}
	if err := ioutil.WriteFile(ConfigFile, yamlFile, 0644); err != nil {
		return fmt.Errorf("failed to write YAML file: %v", err)
	}
	return nil
}

// DefaultAPIClient returns a new Apoxy API client.
func DefaultAPIClient() (*rest.APIClient, error) {
	cfg, err := Load()
	if err != nil {
		return nil, err
	}
	return rest.NewAPIClient(cfg.APIBaseURL, cfg.APIBaseHost, cfg.APIKey, cfg.ProjectID)
}

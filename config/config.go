package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/exp/slog"
	"gopkg.in/yaml.v3"
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
	APIKey       string `yaml:"api_key"`
	ProjectID    string `yaml:"project_id"`
	Verbose      bool   `yaml:"verbose"`
	APIBaseURL   string `yaml:"api_base_url"`
	DashboardURL string `yaml:"dashboard_url"`
}

func getDefaultConfigPath() string {
	return filepath.Join(os.Getenv("HOME"), ".apoxy", "config.yaml")
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
		slog.Debug("Verbose logging enabled")
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

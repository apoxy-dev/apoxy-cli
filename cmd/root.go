package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/exp/slog"
	"gopkg.in/yaml.v3"

	"github.com/apoxy-dev/apoxy-cli/config"
	"github.com/apoxy-dev/apoxy-cli/rest"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "apoxy",
	Short: "Apoxy helps you expose, explore, and evolve your APIs and services.",
	Long: `The Apoxy CLI is the quickest and easiest way to create and control Apoxy proxies.

Start by creating an account on https://apoxy.dev and logging in with 'apoxy auth'.
`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&config.ConfigFile, "config", "", "config file (default is $HOME/.apoxy/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&config.Verbose, "verbose", "v", false, "enable verbose output")
}

// TODO: Move the following functions to a separate file?

// defaultAPIClient returns a new Apoxy API client.
func defaultAPIClient() (*rest.APIClient, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	return rest.NewAPIClient(cfg.APIBaseURL, cfg.APIBaseHost, cfg.APIKey, cfg.ProjectID)
}

// readFileAsString returns a file as a string or an error.
func readFileAsString(filename string) (string, error) {
	slog.Debug("Reading from file", "filename", filename)
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// readStdInAsString returns stdin as a string or an error.
func readStdInAsString() (string, error) {
	slog.Debug("Reading from stdin")
	scanner := bufio.NewScanner(os.Stdin)
	var input string
	for scanner.Scan() {
		text := scanner.Text()
		input += text + "\n"
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("Error reading from stdin: %v", err)
	}
	return input, nil
}

// yamlStringToJSONString converts a YAML string to a JSON string.
func yamlStringToJSONString(yamlString string) (string, error) {
	var data interface{}
	err := yaml.Unmarshal([]byte(yamlString), &data)
	if err != nil {
		return "", err
	}
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

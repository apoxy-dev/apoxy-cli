package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/exp/slog"

	"github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy-cli/pretty"
)

// proxyCmd represents the proxy command
var proxyCmd = &cobra.Command{
	Use:     "proxy",
	Short:   "Manage proxy objects",
	Long:    `The core object in the Apoxy API.`,
	Aliases: []string{"p", "proxies"},
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("proxy called")
	},
}

func fmtProxy(r *v1alpha.Proxy) {
	t := pretty.Table{
		Header: buildProxyHeader(),
		Rows: pretty.Rows{
			buildProxyRow(r),
		},
	}
	t.Print()
}

func buildProxyHeader() pretty.Header {
	return pretty.Header{
		"NAME",
		"PROVIDER",
		"STATUS",
		"ADDRESS",
		"AGE",
	}
}

func buildProxyRow(r *v1alpha.Proxy) []interface{} {
	return []interface{}{
		r.Name,
		r.Spec.Provider,
		r.Status.Phase,
		r.Status.Address,
		pretty.SinceString(r.CreationTimestamp.Time),
	}
}

// getProxyCmd represents the get proxy command
var getProxyCmd = &cobra.Command{
	Use:       "get <name>",
	Short:     "Get proxy objects",
	ValidArgs: []string{"name"},
	Args:      cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := defaultAPIClient()
		if err != nil {
			return err
		}
		r, err := c.Proxy().Get(args[0])
		if err != nil {
			return err
		}
		fmtProxy(r)
		return nil
	},
}

// listProxyCmd represents the list proxy command
var listProxyCmd = &cobra.Command{
	Use:   "list",
	Short: "List proxy objects",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := defaultAPIClient()
		if err != nil {
			return err
		}
		r, err := c.Proxy().List()
		if err != nil {
			return err
		}
		t := pretty.Table{
			Header: buildProxyHeader(),
		}
		for _, p := range r.Items {
			t.Rows = append(t.Rows, buildProxyRow(&p))
		}
		t.Print()
		return nil
	},
}

// proxyFile is the file that contains the configuration to create.
var proxyFile string

// createProxyCmd represents the create proxy command
var createProxyCmd = &cobra.Command{
	Use:   "create [-f filename]",
	Short: "Create proxy objects",
	Long:  `Create proxy objects by providing a configuration as a file or via stdin.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := defaultAPIClient()
		if err != nil {
			return err
		}

		// Load the config to create from a file or stdin.
		var proxyConfig string
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			if proxyFile != "" {
				return fmt.Errorf("cannot use --filename with stdin")
			}
			proxyConfig, err = readStdInAsString()
		} else if proxyFile != "" {
			proxyConfig, err = readFileAsString(proxyFile)
		} else {
			return fmt.Errorf("please provide a configuration via --filename or stdin")
		}

		if err != nil {
			return err
		}

		// Parse proxyConfig into a proxy object.
		proxy := &v1alpha.Proxy{}
		proxyJSON, err := yamlStringToJSONString(proxyConfig)
		if err != nil {
			// Try assuming that the config is a JSON string?
			slog.Debug("failed to parse proxy config as yaml - assuming input is JSON", "error", err)
			proxyJSON = proxyConfig
		}
		err = json.Unmarshal([]byte(proxyJSON), proxy)
		if err != nil {
			return err
		}

		r, err := c.Proxy().Create(proxy)
		if err != nil {
			return err
		}
		fmt.Printf("proxy %q created\n", r.Name)
		return nil
	},
}

// deleteProxyCmd represents the delete proxy command
var deleteProxyCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete proxy objects",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := defaultAPIClient()
		if err != nil {
			return err
		}
		if err = c.Proxy().Delete(args[0]); err != nil {
			return err
		}
		fmt.Printf("proxy %q deleted\n", args[0])
		return nil
	},
}

func init() {
	createProxyCmd.PersistentFlags().
		StringVarP(&proxyFile, "filename", "f", "", "The file that contains the configuration to create.")
	// TODO: add flags for proxy config as raw envoy config

	proxyCmd.AddCommand(getProxyCmd, listProxyCmd, createProxyCmd, deleteProxyCmd)
	rootCmd.AddCommand(proxyCmd)
}

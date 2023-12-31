package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/exp/slog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy-cli/pretty"
)

func fmtProxy(r *v1alpha.Proxy) {
	t := pretty.Table{
		Header: buildProxyHeader(false),
		Rows: pretty.Rows{
			buildProxyRow(r, false),
		},
	}
	t.Print()
}

func buildProxyHeader(labels bool) pretty.Header {
	if labels {
		return pretty.Header{
			"NAME",
			"PROVIDER",
			"STATUS",
			"ADDRESS",
			"AGE",
			"LABELS",
		}
	}
	return pretty.Header{
		"NAME",
		"PROVIDER",
		"STATUS",
		"ADDRESS",
		"AGE",
	}
}

func buildProxyRow(r *v1alpha.Proxy, labels bool) []interface{} {
	if labels {
		return []interface{}{
			r.Name,
			r.Spec.Provider,
			r.Status.Phase,
			r.Status.Address,
			pretty.SinceString(r.CreationTimestamp.Time),
			labelsToString(r.Labels),
		}
	}
	return []interface{}{
		r.Name,
		r.Spec.Provider,
		r.Status.Phase,
		r.Status.Address,
		pretty.SinceString(r.CreationTimestamp.Time),
	}
}

func GetProxy(name string) error {
	c, err := defaultAPIClient()
	if err != nil {
		return err
	}
	r, err := c.Proxy().Get(name)
	if err != nil {
		return err
	}
	fmtProxy(r)
	return nil
}

var showProxyLabels bool

func ListProxies(opts ...metav1.ListOptions) error {
	c, err := defaultAPIClient()
	if err != nil {
		return err
	}
	var r *v1alpha.ProxyList
	if len(opts) > 0 {
		r, err = c.Proxy().ListWithOptions(opts[0])
	} else {
		r, err = c.Proxy().List()
	}
	if err != nil {
		return err
	}
	t := pretty.Table{
		Header: buildProxyHeader(showProxyLabels),
	}
	for _, p := range r.Items {
		t.Rows = append(t.Rows, buildProxyRow(&p, showProxyLabels))
	}
	t.Print()
	return nil
}

// proxyCmd represents the proxy command
var proxyCmd = &cobra.Command{
	Use:     "proxy",
	Short:   "Manage proxy objects",
	Long:    `The core object in the Apoxy API.`,
	Aliases: []string{"p", "proxies"},
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		return ListProxies()
	},
}

// getProxyCmd represents the get proxy command
var getProxyCmd = &cobra.Command{
	Use:       "get <name>",
	Short:     "Get proxy objects",
	ValidArgs: []string{"name"},
	Args:      cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		return GetProxy(args[0])
	},
}

// listProxyCmd represents the list proxy command
var listProxyCmd = &cobra.Command{
	Use:   "list",
	Short: "List proxy objects",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		return ListProxies()
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
		// Load the config to create from a file or stdin.
		var proxyConfig string
		var err error
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

		cmd.SilenceUsage = true

		c, err := defaultAPIClient()
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
		cmd.SilenceUsage = true
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
	listProxyCmd.PersistentFlags().
		BoolVar(&showProxyLabels, "show-labels", false, "Print the proxy's labels.")
	// TODO: add flags for proxy config as raw envoy config

	proxyCmd.AddCommand(getProxyCmd, listProxyCmd, createProxyCmd, deleteProxyCmd)
	rootCmd.AddCommand(proxyCmd)
}

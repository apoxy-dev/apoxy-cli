package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/apoxy-dev/apoxy-cli/config"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "apoxy",
	Short: "Apoxy helps you expose, explore, and evolve your APIs and services.",
	Long: `The Apoxy CLI is the quickest and easiest way to create and control Apoxy proxies.

Start by creating an account on https://apoxy.dev and logging in with 'apoxy auth'.
`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
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

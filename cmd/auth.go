package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/apoxy-dev/apoxy-cli/config"
)

var checkOnly bool

// authCmd represents the auth command
var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authenticate this CLI",
	Long: `If you are not authenticated, this will open a browser window to login via the Apoxy Dashboard.

If your CLI is already authenticated this will return information about your session.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.Load()
		if err != nil {
			fmt.Println(err)
			return
		}

		auth := config.NewAuthenticator(cfg)
		if ok, err := auth.Check(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		} else if ok {
			fmt.Println("Authenticated")
		} else if !checkOnly {
			fmt.Println("Authentication required. Opening browser...")
			auth.Authenticate()
		} else {
			fmt.Println("Invalid authentication")
		}

		if err := config.Store(cfg); err != nil {
			fmt.Println(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(authCmd)
	rootCmd.PersistentFlags().BoolVar(&checkOnly, "check", false, "only check the authentication status")
}

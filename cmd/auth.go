package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/apoxy-dev/apoxy-cli/config"
)

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
		} else if ok {
			fmt.Println("Authenticated")
		} else {
			fmt.Println("Authentication required. Opening browser...")
			auth.Authenticate()
		}

		if err := config.Store(cfg); err != nil {
			fmt.Println(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(authCmd)
}

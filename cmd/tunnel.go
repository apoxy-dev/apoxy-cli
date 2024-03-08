package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/apoxy-dev/apoxy-cli/wg"
)

// tunnelCmd implements the `tunnel` command that creates a secure tunnel
// to the remote Apoxy Edge fabric.
var tunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Create a secure tunnel to the remote Apoxy Edge fabric",
	Long:  "Create a secure tunnel to the remote Apoxy Edge fabric.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true

		t, err := wg.CreateTunnel(cmd.Context())
		if err != nil {
			return fmt.Errorf("unable to create tunnel: %w", err)
		}
		defer t.Close()

		<-cmd.Context().Done()

		return nil
	},
}

func init() {
	rootCmd.AddCommand(tunnelCmd)
}

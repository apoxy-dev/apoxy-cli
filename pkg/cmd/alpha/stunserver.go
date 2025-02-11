package alpha

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/apoxy-dev/apoxy-cli/pkg/stunserver"
)

var stunServerCmd = &cobra.Command{
	Use:   "stunserver",
	Short: "Run a minimal STUN server",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true

		listenAddr, err := cmd.Flags().GetString("listen")
		if err != nil {
			return fmt.Errorf("error getting listen address: %w", err)
		}

		return stunserver.ListenAndServe(cmd.Context(), listenAddr)
	},
}

func init() {
	stunServerCmd.Flags().StringP("listen", "l", "localhost:3478", "Address to listen on")

	alphaCmd.AddCommand(stunServerCmd)
}

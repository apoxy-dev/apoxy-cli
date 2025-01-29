package alpha

import (
	"github.com/spf13/cobra"

	alphatunnel "github.com/apoxy-dev/apoxy-cli/pkg/cmd/alpha/tunnel"
)

var alphaCmd = &cobra.Command{
	Use:   "alpha",
	Short: "Alpha features",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// Cmd returns the alpha command.
func Cmd() *cobra.Command {
	return alphaCmd
}

func init() {
	alphaCmd.AddCommand(alphatunnel.Cmd())
	alphaCmd.AddCommand(alphaProxyCmd)
	alphaCmd.AddCommand(runCmd)
	alphaCmd.AddCommand(stunServerCmd)
}

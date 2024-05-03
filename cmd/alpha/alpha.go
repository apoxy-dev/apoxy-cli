package alpha

import "github.com/spf13/cobra"

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

package alpha

import (
	"context"
	"log"

	"github.com/spf13/cobra"

	"github.com/apoxy-dev/apoxy-cli/internal/apiserver"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run Apoxy server locally",
	Run: func(cmd *cobra.Command, args []string) {
		if err := apiserver.Run(
			context.Background(),
		); err != nil {
			log.Fatalf("could not run server: %v", err)
		}
	},
}

func init() {
	alphaCmd.AddCommand(runCmd)
}

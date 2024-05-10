package alpha

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/apoxy-dev/apoxy-cli/internal/apiserver"
	bpctrl "github.com/apoxy-dev/apoxy-cli/internal/backplane/controllers"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run Apoxy server locally",
	RunE: func(cmd *cobra.Command, args []string) error {
		mgr, err := apiserver.Start(
			cmd.Context(),
		)
		if err != nil {
			return fmt.Errorf("failed to start API server: %w", err)
		}

		projID := uuid.New()
		bp := bpctrl.NewProxyReconciler(
			mgr.GetClient(),
			projID,
			"proxy-uid",
			"machine-name",
		)
		if err := bp.SetupWithManager(cmd.Context(), mgr); err != nil {
			return fmt.Errorf("failed to set up Backplane controller: %w", err)
		}

		return mgr.Start(cmd.Context())
	},
}

func init() {
	alphaCmd.AddCommand(runCmd)
}

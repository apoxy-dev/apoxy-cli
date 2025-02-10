package alpha

import (
	"fmt"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/apoxy-dev/apoxy-cli/api/policy/v1alpha1"
	"github.com/apoxy-dev/apoxy-cli/config"
)

// rateLimitCmd represents the proxy command
var rateLimitCmd = &cobra.Command{
	Use:     "ratelimit",
	Short:   "Manage RateLimit objects",
	Long:    `Manages RateLimit objects within an Apoxy Control Plane.`,
	Aliases: []string{"rl", "ratelimits"},
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

// createrateLimitCmd creates a RateLimit object.
var createrateLimitCmd = &cobra.Command{
	Use:   "create [-f filename]",
	Short: "Create RateLimit objects",
	Long:  `Create RateLimit objects by providing a configuration as a file or via stdin.`,
	RunE: func(cmd *cobra.Command, args []string) error {

		cmd.SilenceUsage = true

		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}

		rl := &v1alpha1.RateLimit{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test",
			},
			Spec: v1alpha1.RateLimitSpec{
				Descriptors: []*v1alpha1.RateLimitDescriptor{
					{
						Key:   "foo",
						Value: "bar",
						RateLimit: &v1alpha1.RateLimitPolicy{
							Unit:            v1alpha1.RateLimitUnitMinute,
							RequestsPerUnit: 2,
						},
					},
				},
			},
		}

		newRL, err := c.PolicyV1alpha1().RateLimits().Create(
			cmd.Context(),
			rl,
			metav1.CreateOptions{},
		)
		if err != nil {
			return err
		}
		fmt.Printf("ratelimit %q created\n", newRL.Name)
		return nil
	},
}

func init() {
	rateLimitCmd.AddCommand(createrateLimitCmd)
}

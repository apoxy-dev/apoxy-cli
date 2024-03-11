package cmd

import (
	"fmt"
	"log"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/cache"

	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy-cli/client/informers"
	"github.com/apoxy-dev/apoxy-cli/wg"
)

const (
	resyncPeriod = 10 * time.Second
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

		c, err := defaultAPIClient()
		if err != nil {
			return fmt.Errorf("unable to create API client: %w", err)
		}
		factory := informers.NewSharedInformerFactory(c, resyncPeriod)
		factory.Start(cmd.Context().Done())
		tunnelInformer := factory.Core().V1alpha().TunnelNodes().Informer()
		tunnelInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				tunnel, ok := obj.(*corev1alpha.TunnelNode)
				if !ok {
					return
				}
				log.Printf("TunnelNode added", "name", tunnel.Name)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				_, ok := oldObj.(*corev1alpha.TunnelNode)
				if !ok {
					return
				}
				newTunnel, ok := newObj.(*corev1alpha.TunnelNode)
				if !ok {
					return
				}
				log.Printf("TunnelNode updated", "name", newTunnel.Name)
			},
			DeleteFunc: func(obj interface{}) {
				tunnel, ok := obj.(*corev1alpha.TunnelNode)
				if !ok {
					return
				}
				log.Printf("TunnelNode deleted", "name", tunnel.Name)
			},
		})
		synced := factory.WaitForCacheSync(cmd.Context().Done())
		for v, s := range synced {
			if !s {
				return fmt.Errorf("informer %s failed to sync", v)
			}
		}

		<-cmd.Context().Done()

		return nil
	},
}

func init() {
	rootCmd.AddCommand(tunnelCmd)
}

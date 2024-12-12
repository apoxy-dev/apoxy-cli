package alpha

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"k8s.io/utils/set"

	configv1alpha "github.com/apoxy-dev/apoxy-cli/api/config/v1alpha1"
	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy-cli/client/informers"
	"github.com/apoxy-dev/apoxy-cli/client/versioned"
	"github.com/apoxy-dev/apoxy-cli/config"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel"
	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard"
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

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("unable to load config: %w", err)
		}

		client, err := config.DefaultAPIClient()
		if err != nil {
			return fmt.Errorf("unable to create API client: %w", err)
		}

		tunnelNodePath, err := cmd.Flags().GetString("tunnel-path")
		if err != nil {
			return fmt.Errorf("unable to get tunnel path: %w", err)
		}

		tunnelNodeName, err := cmd.Flags().GetString("tunnel-name")
		if err != nil {
			return fmt.Errorf("unable to get tunnel name: %w", err)
		}

		var tunnelNode *corev1alpha.TunnelNode
		if tunnelNodePath != "" {
			tunnelNode, err = loadTunnelNodeFromPath(tunnelNodePath)
			if err != nil {
				return fmt.Errorf("unable to load tunnel node: %w", err)
			}

			tunnelNodeName = tunnelNode.Name

			// Clean up the tunnel node after the command completes.
			defer func() {
				if err := client.CoreV1alpha().TunnelNodes().Delete(
					context.Background(),
					tunnelNodeName,
					metav1.DeleteOptions{},
				); err != nil {
					slog.Warn("Failed to delete TunnelNode", slog.Any("error", err))
				}
			}()
		} else if tunnelNodeName != "" {
			tunnelNode, err = client.CoreV1alpha().TunnelNodes().Get(
				cmd.Context(),
				tunnelNodeName,
				metav1.GetOptions{},
			)
			if err != nil {
				return fmt.Errorf("unable to get tunnel node: %w", err)
			}
		} else {
			return fmt.Errorf("either --tunnel-path or --tunnel-name must be specified")
		}

		var tun tunnel.Tunnel
		if cfg.Tunnel != nil && cfg.Tunnel.Mode == configv1alpha.TunnelModeUserspace {
			socksPort := uint16(1080)
			if cfg.Tunnel.SocksPort != nil {
				socksPort = uint16(*cfg.Tunnel.SocksPort)
			}

			tun, err = tunnel.CreateUserspaceTunnel(cmd.Context(), client.ProjectID, tunnelNodeName, socksPort, cfg.Verbose)
		} else {
			tun, err = tunnel.CreateKernelTunnel(cmd.Context(), client.ProjectID, tunnelNodeName)
		}
		if err != nil {
			return fmt.Errorf("unable to create tunnel: %w", err)
		}
		defer tun.Close()

		// TODO: Listen for changes to our peerrefs and update the tunnel accordingly.
		factory := informers.NewSharedInformerFactoryWithOptions(
			client,
			resyncPeriod,
		)

		doneCh := make(chan struct{})
		tunnelInformer := factory.Core().V1alpha().TunnelNodes().Informer()
		tunnelInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				updatedTunnelNode, ok := obj.(*corev1alpha.TunnelNode)
				if !ok {
					return
				}

				if updatedTunnelNode.Name == tunnelNodeName {
					tunnelNode = updatedTunnelNode
				} else {
					var err error
					tunnelNode, err = client.CoreV1alpha().TunnelNodes().Get(cmd.Context(), tunnelNodeName, metav1.GetOptions{})
					if err != nil {
						slog.Warn("Failed to get TunnelNode", slog.String("name", tunnelNodeName), slog.Any("error", err))
						return
					}

					// Do we have a reference to the object?
					var foundRef bool
					for _, peer := range tunnelNode.Spec.Peers {
						if peer.TunnelNodeRef != nil && peer.TunnelNodeRef.Name == updatedTunnelNode.Name {
							foundRef = true
							break
						}
					}
					if !foundRef {
						// Nothing for us to do.
						return
					}
				}

				syncTunnelNode(cmd.Context(), client, tunnelNode, tun)
			},
			UpdateFunc: func(oldObj, newObj any) {
				updatedTunnelNode, ok := newObj.(*corev1alpha.TunnelNode)
				if !ok {
					return
				}

				if updatedTunnelNode.Name == tunnelNodeName {
					tunnelNode = updatedTunnelNode
				} else {
					var err error
					tunnelNode, err = client.CoreV1alpha().TunnelNodes().Get(cmd.Context(), tunnelNodeName, metav1.GetOptions{})
					if err != nil {
						slog.Warn("Failed to get TunnelNode", slog.String("name", tunnelNodeName), slog.Any("error", err))
						return
					}

					// Do we have a reference to the object?
					var foundRef bool
					for _, peer := range tunnelNode.Spec.Peers {
						if peer.TunnelNodeRef != nil && peer.TunnelNodeRef.Name == updatedTunnelNode.Name {
							foundRef = true
							break
						}
					}
					if !foundRef {
						// Nothing for us to do.
						return
					}
				}

				syncTunnelNode(cmd.Context(), client, tunnelNode, tun)
			},
			DeleteFunc: func(obj any) {
				tunnelNode, ok := obj.(*corev1alpha.TunnelNode)
				if !ok {
					return
				}

				slog.Info("TunnelNode deleted", slog.String("name", tunnelNode.Name))

				doneCh <- struct{}{}
			},
		})

		factory.Start(cmd.Context().Done())
		synced := factory.WaitForCacheSync(cmd.Context().Done())
		for v, s := range synced {
			if !s {
				return fmt.Errorf("informer %s failed to sync", v)
			}
		}

		// Set the initial status of the TunnelNode object.
		tunnelNode.Status.Phase = corev1alpha.NodePhaseReady
		tunnelNode.Status.PublicKey = tun.PublicKey()
		tunnelNode.Status.ExternalAddress = tun.ExternalAddress().String()
		tunnelNode.Status.InternalAddress = tun.InternalAddress().String()

		// Create the TunnelNode object in the API.
		if err := upsertTunnelNode(cmd.Context(), client, tunnelNode); err != nil {
			return err
		}

		// Wait for the TunnelNode object to be deleted, or for the command to be cancelled.
		select {
		case <-doneCh:
		case <-cmd.Context().Done():
		}

		return nil
	},
}

func init() {
	tunnelCmd.Flags().String("tunnel-path", "", "Path to the TunnelNode to create in the API.")
	tunnelCmd.Flags().String("tunnel-name", "", "Name of the TunnelNode to manage. Must not be used with --tunnel-path.")

	alphaCmd.AddCommand(tunnelCmd)
}

func syncTunnelNode(ctx context.Context, client versioned.Interface, tunnelNode *corev1alpha.TunnelNode, tun tunnel.Tunnel) {
	peerPublicKeys := set.New[string]()
	peerTunnelNodes := map[string]*corev1alpha.TunnelNode{}

	for _, peer := range tunnelNode.Spec.Peers {
		if peer.TunnelNodeRef != nil {
			peerTunnelNode, err := client.CoreV1alpha().TunnelNodes().Get(ctx, peer.TunnelNodeRef.Name, metav1.GetOptions{})
			if err != nil && !errors.IsNotFound(err) {
				slog.Warn("Failed to get peer", slog.String("name", peer.TunnelNodeRef.Name), slog.Any("error", err))
				continue
			}

			if peerTunnelNode.Status.PublicKey != "" {
				peerPublicKeys.Insert(peerTunnelNode.Status.PublicKey)
				peerTunnelNodes[peerTunnelNode.Status.PublicKey] = peerTunnelNode
			}
		}
	}

	knownPeers, err := tun.Peers()
	if err != nil {
		slog.Error("Failed to get known peers", slog.String("name", tunnelNode.Name), slog.Any("error", err))
		return
	}

	for peerPublicKey := range peerPublicKeys.Difference(knownPeers) {
		peerTunnelNode := peerTunnelNodes[peerPublicKey]

		peerConf := &wireguard.PeerConfig{
			PublicKey:  ptr.To(peerTunnelNode.Status.PublicKey),
			Endpoint:   ptr.To(peerTunnelNode.Status.ExternalAddress),
			AllowedIPs: []string{peerTunnelNode.Status.InternalAddress},
		}

		if err := tun.AddPeer(peerConf); err != nil {
			slog.Error("Failed to add peer", slog.String("name", peerTunnelNode.Name), slog.Any("error", err))
		}
	}

	for peerPublicKey := range knownPeers.Difference(peerPublicKeys) {
		if err := tun.RemovePeer(peerPublicKey); err != nil {
			slog.Error("Failed to remove peer", slog.String("publicKey", peerPublicKey), slog.Any("error", err))
		}
	}
}

func loadTunnelNodeFromPath(path string) (*corev1alpha.TunnelNode, error) {
	yamlFile, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	obj, gvk, err := decodeFn(yamlFile, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decode TunnelNode: %w", err)
	}

	tunnelNode, ok := obj.(*corev1alpha.TunnelNode)
	if !ok {
		return nil, fmt.Errorf("not a TunnelNode object: %v", gvk)
	}

	return tunnelNode, nil
}

func upsertTunnelNode(ctx context.Context, client versioned.Interface, tunnelNode *corev1alpha.TunnelNode) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		_, err := client.CoreV1alpha().TunnelNodes().Create(ctx, tunnelNode, metav1.CreateOptions{})
		if errors.IsAlreadyExists(err) {
			existingTunnelNode, err := client.CoreV1alpha().TunnelNodes().Get(ctx, tunnelNode.Name, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("failed to get existing TunnelNode: %w", err)
			}

			tunnelNode.ResourceVersion = existingTunnelNode.ResourceVersion

			_, err = client.CoreV1alpha().TunnelNodes().Update(ctx, tunnelNode, metav1.UpdateOptions{})
			if err != nil {
				return fmt.Errorf("failed to update existing TunnelNode: %w", err)
			}

			_, err = client.CoreV1alpha().TunnelNodes().UpdateStatus(ctx, tunnelNode, metav1.UpdateOptions{})
			if err != nil {
				return fmt.Errorf("failed to update existing TunnelNode status: %w", err)
			}

			return nil
		} else if err != nil {
			return fmt.Errorf("failed to create TunnelNode: %w", err)
		}

		return nil
	})
}

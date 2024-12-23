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
	corev1alphaclient "github.com/apoxy-dev/apoxy-cli/client/listers/core/v1alpha"
	"github.com/apoxy-dev/apoxy-cli/client/versioned"
	"github.com/apoxy-dev/apoxy-cli/config"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel"
	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard"
)

const (
	// resyncPeriod is the interval at which the informer will resync its cache.
	resyncPeriod = 30 * time.Second
)

// tunnelCmd implements the `tunnel` command that creates a secure tunnel
// to the remote Apoxy Edge fabric.
var tunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Create a secure tunnel to the remote Apoxy Edge fabric",
	Long:  "Create a secure tunnel to the remote Apoxy Edge fabric.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
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

		return runTunnel(ctx, cfg, client, tunnelNodePath, tunnelNodeName)
	},
}

func init() {
	tunnelCmd.Flags().String("tunnel-path", "", "Path to the TunnelNode to create in the API.")
	tunnelCmd.Flags().String("tunnel-name", "", "Name of the TunnelNode to manage. Must not be used with --tunnel-path.")

	alphaCmd.AddCommand(tunnelCmd)
}

func runTunnel(ctx context.Context, cfg *configv1alpha.Config, client versioned.Interface, tunnelNodePath, tunnelNodeName string) error {
	var tunnelNode *corev1alpha.TunnelNode
	var err error
	if tunnelNodePath != "" {
		tunnelNode, err = loadTunnelNodeFromPath(tunnelNodePath)
		if err != nil {
			return fmt.Errorf("unable to load tunnel node: %w", err)
		}

		tunnelNodeName = tunnelNode.Name

		// Clean up the tunnel node after the command completes.
		defer func() {
			slog.Debug("Deleting TunnelNode", slog.String("name", tunnelNodeName))

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
			ctx,
			tunnelNodeName,
			metav1.GetOptions{},
		)
		if err != nil {
			return fmt.Errorf("unable to get tunnel node: %w", err)
		}
	} else {
		return fmt.Errorf("either --tunnel-path or --tunnel-name must be specified")
	}

	stunServers := tunnel.DefaultSTUNServers
	if cfg.Tunnel != nil && len(cfg.Tunnel.STUNServers) > 0 {
		stunServers = cfg.Tunnel.STUNServers
	}

	var tun tunnel.Tunnel
	if cfg.Tunnel != nil && cfg.Tunnel.Mode == configv1alpha.TunnelModeUserspace {
		socksPort := uint16(1080)
		if cfg.Tunnel.SocksPort != nil {
			socksPort = uint16(*cfg.Tunnel.SocksPort)
		}

		tun, err = tunnel.CreateUserspaceTunnel(ctx, cfg.CurrentProject, tunnelNodeName, socksPort, stunServers, cfg.Verbose)
	} else {
		tun, err = tunnel.CreateKernelTunnel(ctx, cfg.CurrentProject, tunnelNodeName, stunServers)
	}
	if err != nil {
		return fmt.Errorf("unable to create tunnel: %w", err)
	}
	defer tun.Close()

	slog.Debug("Tunnel created",
		slog.String("name", tunnelNodeName), slog.String("publicKey", tun.PublicKey()),
		slog.String("internalAddress", tun.InternalAddress().String()))

	factory := informers.NewSharedInformerFactoryWithOptions(
		client,
		resyncPeriod,
	)

	tunnelNodeInformer := factory.Core().V1alpha().TunnelNodes().Informer()
	tunnelNodeLister := factory.Core().V1alpha().TunnelNodes().Lister()

	doneCh := make(chan struct{})
	tunnelNodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			updatedTunnelNode, ok := obj.(*corev1alpha.TunnelNode)
			if !ok {
				return
			}

			handleTunnelNodeUpdate(tunnelNodeLister, tunnelNodeName, tun, updatedTunnelNode)
		},
		UpdateFunc: func(_, newObj any) {
			updatedTunnelNode, ok := newObj.(*corev1alpha.TunnelNode)
			if !ok {
				return
			}

			handleTunnelNodeUpdate(tunnelNodeLister, tunnelNodeName, tun, updatedTunnelNode)
		},
		DeleteFunc: func(obj any) {
			deletedTunnelNode, ok := obj.(*corev1alpha.TunnelNode)
			if !ok {
				return
			}

			if deletedTunnelNode.Name != tunnelNodeName {
				// Nothing for us to do.
				return
			}

			doneCh <- struct{}{}
		},
	})

	factory.Start(ctx.Done())
	synced := factory.WaitForCacheSync(ctx.Done())
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

	// Create/update the TunnelNode object in the API.
	slog.Debug("Creating/updating TunnelNode", slog.String("name", tunnelNode.Name))

	if err := upsertTunnelNode(ctx, client, tunnelNode); err != nil {
		return err
	}

	// Wait for the TunnelNode object to be deleted, or for the command to be cancelled.
	select {
	case <-doneCh:
	case <-ctx.Done():
	}

	return nil
}

// handleTunnelNodeUpdate is called every time a TunnelNode object is added or updated.
func handleTunnelNodeUpdate(tunnelNodeLister corev1alphaclient.TunnelNodeLister,
	tunnelNodeName string, tun tunnel.Tunnel, updatedTunnelNode *corev1alpha.TunnelNode) {
	var tunnelNode *corev1alpha.TunnelNode
	if updatedTunnelNode.Name == tunnelNodeName {
		// The updated object is the one we are managing.
		tunnelNode = updatedTunnelNode
	} else {
		// A different object was updated. We need to check if it references the object we are managing.
		var err error
		tunnelNode, err = tunnelNodeLister.Get(tunnelNodeName)
		if err != nil {
			if !errors.IsNotFound(err) {
				slog.Warn("Failed to get TunnelNode",
					slog.String("name", tunnelNodeName), slog.Any("error", err))
			}
			return
		}

		// Do we have a reference to the object?
		var foundRef bool
		for _, peer := range tunnelNode.Spec.Peers {
			if peer.TunnelNodeRef != nil {
				if peer.TunnelNodeRef.Name == updatedTunnelNode.Name {
					foundRef = true
					break
				}
			} else if peer.LabelSelector != nil {
				selector, err := metav1.LabelSelectorAsSelector(peer.LabelSelector)
				if err != nil {
					slog.Warn("Invalid label selector", slog.Any("error", err))
					continue
				}

				peerTunnelNodesList, err := tunnelNodeLister.List(selector)
				if err != nil {
					slog.Warn("Failed to list TunnelNodes", slog.Any("error", err))
					continue
				}

				for _, peerTunnelNode := range peerTunnelNodesList {
					if peerTunnelNode.Name == updatedTunnelNode.Name {
						foundRef = true
						break
					}
				}
			}
		}

		if !foundRef {
			// The updated object is not referenced by the object we are managing.
			return
		}
	}

	syncTunnelNode(tunnelNodeLister, tunnelNode, tun)
}

// syncTunnelNode reconciles the state of our TunnelNode object with the state of the tunnel.
func syncTunnelNode(tunnelNodeLister corev1alphaclient.TunnelNodeLister,
	tunnelNode *corev1alpha.TunnelNode, tun tunnel.Tunnel) {
	peerPublicKeys := set.New[string]()
	peerTunnelNodes := map[string]*corev1alpha.TunnelNode{}

	for _, peer := range tunnelNode.Spec.Peers {
		if peer.TunnelNodeRef != nil {
			peerTunnelNode, err := tunnelNodeLister.Get(peer.TunnelNodeRef.Name)
			if err != nil {
				if !errors.IsNotFound(err) {
					slog.Warn("Failed to get peer", slog.String("name", peer.TunnelNodeRef.Name), slog.Any("error", err))
				}
				continue
			}

			if peerTunnelNode.Status.PublicKey != "" {
				peerPublicKeys.Insert(peerTunnelNode.Status.PublicKey)
				peerTunnelNodes[peerTunnelNode.Status.PublicKey] = peerTunnelNode
			}
		} else if peer.LabelSelector != nil {
			selector, err := metav1.LabelSelectorAsSelector(peer.LabelSelector)
			if err != nil {
				slog.Warn("Invalid label selector", slog.Any("error", err))
				continue
			}

			peerTunnelNodeList, err := tunnelNodeLister.List(selector)
			if err != nil {
				slog.Warn("Failed to list TunnelNodes", slog.Any("error", err))
				continue
			}

			for _, peerTunnelNode := range peerTunnelNodeList {
				if peerTunnelNode.Status.PublicKey != "" {
					peerPublicKeys.Insert(peerTunnelNode.Status.PublicKey)
					peerTunnelNodes[peerTunnelNode.Status.PublicKey] = peerTunnelNode
				}
			}
		}
	}

	knownPeers, err := tun.Peers()
	if err != nil {
		slog.Error("Failed to get known peers", slog.String("name", tunnelNode.Name), slog.Any("error", err))
		return
	}

	knownPeerPublicKeys := set.New[string]()
	for _, peerConf := range knownPeers {
		knownPeerPublicKeys.Insert(*peerConf.PublicKey)
	}

	// Check for peers with no longer valid configurations.
	for _, peerConf := range knownPeers {
		peerTunnelNode, ok := peerTunnelNodes[*peerConf.PublicKey]
		if !ok {
			continue
		}

		// Check if the peer configuration has changed.
		var peerConfChanged bool
		if *peerConf.PublicKey != peerTunnelNode.Status.PublicKey {
			peerConfChanged = true
		}
		if (peerConf.Endpoint == nil && peerTunnelNode.Status.ExternalAddress != "") ||
			(peerConf.Endpoint != nil && *peerConf.Endpoint != peerTunnelNode.Status.ExternalAddress) {
			peerConfChanged = true
		}
		if (len(peerConf.AllowedIPs) == 0 && peerTunnelNode.Status.InternalAddress != "") ||
			len(peerConf.AllowedIPs) > 0 && peerConf.AllowedIPs[0] != peerTunnelNode.Status.InternalAddress {
			peerConfChanged = true
		}

		if peerConfChanged {
			slog.Debug("Peer configuration changed", slog.String("name", peerTunnelNode.Name))

			if err := tun.RemovePeer(*peerConf.PublicKey); err != nil {
				slog.Error("Failed to remove peer", slog.String("name", peerTunnelNode.Name), slog.Any("error", err))
			}

			// Will be re-added below with the new configuration.
			peerPublicKeys.Delete(*peerConf.PublicKey)
		}
	}

	// New peers to add.
	for peerPublicKey := range peerPublicKeys.Difference(knownPeerPublicKeys) {
		peerTunnelNode := peerTunnelNodes[peerPublicKey]

		peerConf := &wireguard.PeerConfig{
			PublicKey:  ptr.To(peerTunnelNode.Status.PublicKey),
			Endpoint:   ptr.To(peerTunnelNode.Status.ExternalAddress),
			AllowedIPs: []string{peerTunnelNode.Status.InternalAddress},
		}

		slog.Debug("Adding peer",
			slog.String("name", peerTunnelNode.Name),
			slog.String("publicKey", peerPublicKey),
			slog.String("endpoint", peerTunnelNode.Status.ExternalAddress))

		if err := tun.AddPeer(peerConf); err != nil {
			slog.Error("Failed to add peer", slog.String("name", peerTunnelNode.Name), slog.Any("error", err))
		}
	}

	// Peers to remove.
	for peerPublicKey := range knownPeerPublicKeys.Difference(peerPublicKeys) {
		slog.Debug("Removing peer", slog.String("publicKey", peerPublicKey))

		if err := tun.RemovePeer(peerPublicKey); err != nil {
			slog.Error("Failed to remove peer", slog.String("publicKey", peerPublicKey), slog.Any("error", err))
		}
	}
}

// upsertTunnelNode creates or updates a TunnelNode object in the API.
func upsertTunnelNode(ctx context.Context, client versioned.Interface, tunnelNode *corev1alpha.TunnelNode) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		existingTunnelNode, err := client.CoreV1alpha().TunnelNodes().Get(ctx, tunnelNode.Name, metav1.GetOptions{})
		if err == nil {
			// Update the existing TunnelNode.
			tunnelNode.ResourceVersion = existingTunnelNode.ResourceVersion

			_, err = client.CoreV1alpha().TunnelNodes().Update(ctx, tunnelNode, metav1.UpdateOptions{})
			if err != nil {
				return fmt.Errorf("failed to update existing TunnelNode: %w", err)
			}
		} else {
			// Create a new TunnelNode.
			if _, err := client.CoreV1alpha().TunnelNodes().Create(ctx, tunnelNode, metav1.CreateOptions{}); err != nil {
				return fmt.Errorf("failed to create TunnelNode: %w", err)
			}

			existingTunnelNode, err := client.CoreV1alpha().TunnelNodes().Get(ctx, tunnelNode.Name, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("failed to get newly created TunnelNode: %w", err)
			}

			tunnelNode.ResourceVersion = existingTunnelNode.ResourceVersion
		}

		_, err = client.CoreV1alpha().TunnelNodes().UpdateStatus(ctx, tunnelNode, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update TunnelNode status: %w", err)
		}

		return nil
	})
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

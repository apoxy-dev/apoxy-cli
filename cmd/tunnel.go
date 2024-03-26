package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy-cli/client/informers"
	"github.com/apoxy-dev/apoxy-cli/wg"
)

const (
	resyncPeriod = 10 * time.Second
)

type tunnelPeer struct {
	PubKeyHex                   string
	Endpoint                    netip.AddrPort
	AllowedIPs                  []net.IPNet
	PersistentKeepaliveInterval time.Duration
}

// tunnelCmd implements the `tunnel` command that creates a secure tunnel
// to the remote Apoxy Edge fabric.
var tunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Create a secure tunnel to the remote Apoxy Edge fabric",
	Long:  "Create a secure tunnel to the remote Apoxy Edge fabric.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true

		c, err := defaultAPIClient()
		if err != nil {
			return fmt.Errorf("unable to create API client: %w", err)
		}

		// TODO(dsky): Allow the user to specify the endpoint.
		host, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("unable to get hostname: %w", err)
		}

		t, err := wg.CreateTunnel(cmd.Context(), c.ProjectID, host)
		if err != nil {
			return fmt.Errorf("unable to create tunnel: %w", err)
		}
		defer t.Close()

		factory := informers.NewSharedInformerFactory(c, resyncPeriod)
		tunnelInformer := factory.Core().V1alpha().TunnelNodes().Informer()
		proxyPeers := make(map[string]*tunnelPeer)
		tunnelInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				tunnel, ok := obj.(*corev1alpha.TunnelNode)
				if !ok {
					return
				}
				fmt.Printf("Tunnel %s added\n", tunnel.Name)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				newTunnel, ok := newObj.(*corev1alpha.TunnelNode)
				if !ok {
					return
				}
				fmt.Printf("Tunnel %s updated\n", newTunnel.Name)

				// Create a new peer for the tunnel.
				newPeers := make(map[string]*tunnelPeer)
				for _, p := range newTunnel.Status.PeerStatuses {
					if _, ok := proxyPeers[p.PubKey]; !ok {
						pubKey, err := wgtypes.ParseKey(p.PubKey)
						if err != nil {
							fmt.Printf("Failed to parse peer public key: %v", err)
							continue
						}
						extAddrPort, err := netip.ParseAddrPort(p.ExternalAddress)
						if err != nil {
							fmt.Printf("Failed to parse peer address: %v", err)
							continue
						}
						intAddr, err := netip.ParseAddr(p.InternalAddress)
						if err != nil {
							fmt.Printf("Failed to parse peer address: %v", err)
							continue
						}
						if !intAddr.Is6() {
							fmt.Printf("Internal address must be an IPv6 address")
							continue
						}
						peer := &tunnelPeer{
							PubKeyHex: hex.EncodeToString(pubKey[:]),
							Endpoint:  extAddrPort,
							AllowedIPs: []net.IPNet{
								{
									IP:   intAddr.AsSlice(),
									Mask: net.CIDRMask(128, 128),
								},
							},
							PersistentKeepaliveInterval: 15 * time.Second,
						}
						if err := t.AddPeer(
							peer.PubKeyHex,
							peer.Endpoint,
							peer.AllowedIPs,
							peer.PersistentKeepaliveInterval,
						); err != nil {
							fmt.Printf("Failed to add peer: %v", err)
							continue
						}
						newPeers[p.PubKey] = peer
						delete(proxyPeers, p.PubKey)
					}
				}
				// Remove any peers that are no longer present.
				for _, p := range proxyPeers {
					if err := t.RemovePeer(p.PubKeyHex); err != nil {
						fmt.Printf("Failed to remove peer: %v", err)
					}
				}
				proxyPeers = newPeers
			},
			DeleteFunc: func(obj interface{}) {
				tunnel, ok := obj.(*corev1alpha.TunnelNode)
				if !ok {
					return
				}
				fmt.Printf("Tunnel %s deleted\n", tunnel.Name)
			},
		})
		factory.Start(cmd.Context().Done()) // Must be called after new informers are added.
		synced := factory.WaitForCacheSync(cmd.Context().Done())
		for v, s := range synced {
			if !s {
				return fmt.Errorf("informer %s failed to sync", v)
			}
		}

		_, err = c.CoreV1alpha().TunnelNodes().Create(
			cmd.Context(),
			&corev1alpha.TunnelNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: host,
				},
				Spec: corev1alpha.TunnelNodeSpec{
					PubKey:          t.PubKey().String(),
					ExternalAddress: t.ExternalAddress().String(),
					InternalAddress: t.InternalAddress().String(),
				},
				Status: corev1alpha.TunnelNodeStatus{
					Phase: corev1alpha.NodePhasePending,
				},
			},
			metav1.CreateOptions{},
		)
		if err != nil {
			return fmt.Errorf("unable to create TunnelNode: %w", err)
		}

		<-cmd.Context().Done()
		fmt.Printf("Shutting down...\n")
		dCtx := context.Background() // Use a new context to ensure the tunnel is closed.
		if err := c.CoreV1alpha().TunnelNodes().Delete(
			dCtx,
			host,
			metav1.DeleteOptions{},
		); err != nil {
			return fmt.Errorf("unable to delete TunnelNode: %w", err)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(tunnelCmd)
}

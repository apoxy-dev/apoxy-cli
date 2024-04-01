package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"html/template"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/goombaio/namegenerator"
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

var demoProxyConfigTmpl = template.Must(template.New("demoProxyConfig").Parse(`
admin:
  address:
    socket_address: { address: 127.0.0.1, port_value: 9901 }

static_resources:
  listeners:
  - name: listener_0
    address:
      socket_address: { address: 0.0.0.0, port_value: {{ .Port }} }
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          codec_type: AUTO
          access_log:
          - name: envoy.access_loggers.file
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
              path: /var/log/accesslogs
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - match: { prefix: "/" }
                route:
                  cluster: some_service
                  auto_host_rewrite: true
          http_filters:
          - name: envoy.filters.http.tap
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.tap.v3.Tap
              common_config:
                static_config:
                  match_config:
                    any_match: true
                  output_config:
                    sinks:
                      - format: PROTO_BINARY
                        file_per_tap:
                          path_prefix: /var/log/taps/
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
  - name: some_service
    connect_timeout: 0.25s
    type: STATIC
    dns_lookup_family: V4_ONLY
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: some_service
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: "{{ .Addr }}"
                port_value: {{ .Port }}`))

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
		isDemo, err := cmd.Flags().GetBool("demo")
		if err != nil {
			return fmt.Errorf("unable to get demo flag: %w", err)
		}
		var port int
		if isDemo {
			var err error
			port, err = cmd.Flags().GetInt("port")
			if err != nil {
				return fmt.Errorf("unable to get port flag: %w", err)
			}
			if port == 0 {
				return fmt.Errorf("port must be specified in demo mode")
			}
		}
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

		if isDemo {
			pName := namegenerator.NewNameGenerator(time.Now().UTC().UnixNano()).Generate()

			// 127.0.0.1 ipv4 in ipv6.
			addr := t.InternalAddress().Addr().As16()
			addr[12] = 127
			addr[13] = 0
			addr[14] = 0
			addr[15] = 1

			proxyCfg := &strings.Builder{}
			if err := demoProxyConfigTmpl.Execute(proxyCfg, map[string]interface{}{
				"Addr": netip.AddrFrom16(addr).String(),
				"Port": port,
			}); err != nil {
				return fmt.Errorf("unable to execute proxy config template: %w", err)
			}

			_, err := c.CoreV1alpha().Proxies().Create(
				cmd.Context(),
				&corev1alpha.Proxy{
					ObjectMeta: metav1.ObjectMeta{
						Name: pName,
						Labels: map[string]string{
							"apoxy.dev/demo": "true",
						},
					},
					Spec: corev1alpha.ProxySpec{
						Type:       corev1alpha.ProxyTypeEnvoy,
						Provider:   corev1alpha.InfraProviderCloud,
						ConfigData: proxyCfg.String(),
					},
				},
				metav1.CreateOptions{},
			)
			if err != nil {
				return fmt.Errorf("unable to create proxy: %w", err)
			}

			fmt.Printf("Proxy %s created\n", pName)
		}

		proxyInformer := factory.Core().V1alpha().Proxies().Informer()
		proxyInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			UpdateFunc: func(oldObj, newObj interface{}) {
				newProxy, ok := newObj.(*corev1alpha.Proxy)
				if !ok {
					return
				}
				if newProxy.Status.Phase == corev1alpha.ProxyPhaseRunning &&
					newProxy.Status.Address != "" {
					fmt.Printf("Proxy %s is ready at %s\n", newProxy.Name, newProxy.Status.Address)
				}
			},
		})

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
					} else {
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
	tunnelCmd.Flags().Bool("demo", false, "Creates a demo Proxy with a single upstream for this tunnel. Requires --port flag.")
	tunnelCmd.Flags().Int("port", 0, "The port to use for the demo Proxy.")
	rootCmd.AddCommand(tunnelCmd)
}

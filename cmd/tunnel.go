package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/goombaio/namegenerator"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy-cli/client/informers"
	"github.com/apoxy-dev/apoxy-cli/client/versioned"
	"github.com/apoxy-dev/apoxy-cli/config"
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

var (
	printDemoProxyStatusOnce sync.Once
)

func createDemoProxy(
	ctx context.Context,
	c versioned.Interface,
	intAddr netip.Addr, port int,
) (error, func()) {
	pName := namegenerator.NewNameGenerator(time.Now().UTC().UnixNano()).Generate()
	factory := informers.NewSharedInformerFactoryWithOptions(
		c,
		resyncPeriod,
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = "metadata.name=" + pName
		}),
	)

	// 127.0.0.1 ipv4 in ipv6.
	addr := intAddr.As16()
	addr[12] = 127
	addr[13] = 0
	addr[14] = 0
	addr[15] = 1

	proxyCfg := &strings.Builder{}
	if err := demoProxyConfigTmpl.Execute(proxyCfg, map[string]interface{}{
		"Addr": netip.AddrFrom16(addr).String(),
		"Port": port,
	}); err != nil {
		return fmt.Errorf("unable to execute proxy config template: %w", err), nil
	}

	fmt.Printf("Creating demo proxy %s with port %d...\n", pName, port)

	_, err := c.CoreV1alpha().Proxies().Create(
		ctx,
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
		return fmt.Errorf("unable to create proxy: %w", err), nil
	}

	proxyInformer := factory.Core().V1alpha().Proxies().Informer()
	proxyInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(oldObj, newObj interface{}) {
			newProxy, ok := newObj.(*corev1alpha.Proxy)
			if !ok {
				return
			}
			if newProxy.ObjectMeta.Name == pName &&
				newProxy.Status.Phase == corev1alpha.ProxyPhaseRunning &&
				newProxy.Status.Address != "" {
				printDemoProxyStatusOnce.Do(func() {
					fmt.Printf("Proxy %s is ready at %s:%d\n", newProxy.Name, newProxy.Status.Address, port)
				})
			}
		},
	})
	factory.Start(ctx.Done()) // Must be called after new informers are added.
	factory.WaitForCacheSync(ctx.Done())

	return nil, func() {
		ctx := context.Background()
		fmt.Printf("Deleting demo proxy %s...\n", pName)
		c.CoreV1alpha().Proxies().Delete(ctx, pName, metav1.DeleteOptions{})
	}
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

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("unable to load config: %w", err)
		}

		c, err := defaultAPIClient()
		if err != nil {
			return fmt.Errorf("unable to create API client: %w", err)
		}

		// TODO(dsky): Allow the user to specify the endpoint.
		host, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("unable to get hostname: %w", err)
		}

		t, err := wg.CreateTunnel(cmd.Context(), c.ProjectID, host, cfg.Verbose)
		if err != nil {
			return fmt.Errorf("unable to create tunnel: %w", err)
		}
		defer t.Close()

		if isDemo {
			err, cleanup := createDemoProxy(cmd.Context(), c, t.InternalAddress().Addr(), port)
			if err != nil {
				return fmt.Errorf("unable to create demo proxy: %w", err)
			}
			defer cleanup()
		}

		factory := informers.NewSharedInformerFactoryWithOptions(
			c,
			resyncPeriod,
			informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
				opts.FieldSelector = "metadata.name=" + host
			}),
		)
		tunnelInformer := factory.Core().V1alpha().TunnelNodes().Informer()
		proxyPeers := make(map[string]*tunnelPeer)
		doneCh := make(chan struct{})
		tunnelInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			UpdateFunc: func(oldObj, newObj interface{}) {
				newTunnel, ok := newObj.(*corev1alpha.TunnelNode)
				if !ok {
					return
				}
				slog.Debug("Tunnel updated", "tunnel", newTunnel.Name)

				// Create a new peer for the tunnel.
				newPeers := make(map[string]*tunnelPeer)
				for _, p := range newTunnel.Status.PeerStatuses {
					if _, ok := proxyPeers[p.PubKey]; !ok {
						pubKey, err := wgtypes.ParseKey(p.PubKey)
						if err != nil {
							slog.Error("Failed to parse peer public key", "err", err)
							continue
						}
						extAddrPort, err := netip.ParseAddrPort(p.ExternalAddress)
						if err != nil {
							slog.Error("Failed to parse peer address", "err", err)
							continue
						}
						intAddr, err := netip.ParseAddr(p.InternalAddress)
						if err != nil {
							slog.Error("Failed to parse peer address", "err", err)
							continue
						}
						if !intAddr.Is6() {
							slog.Error("Internal address must be an IPv6 address")
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

						slog.Debug("Adding peer", "peer", peer)

						if err := t.AddPeer(
							peer.PubKeyHex,
							peer.Endpoint,
							peer.AllowedIPs,
							peer.PersistentKeepaliveInterval,
						); err != nil {
							slog.Error("Failed to add peer", "err", err)
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
						slog.Error("Failed to remove peer", "err", err)
					}
				}
				proxyPeers = newPeers
			},
			DeleteFunc: func(obj interface{}) {
				doneCh <- struct{}{}
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
		fmt.Printf("Cleaning up tunnel...\n")
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

//go:build linux

package main

import (
	"flag"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/apoxy-dev/apoxy-cli/pkg/apiserver"
	"github.com/apoxy-dev/apoxy-cli/pkg/log"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel"
	tunnelnet "github.com/apoxy-dev/apoxy-cli/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel/router"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel/token"

	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(corev1alpha.Install(scheme))
}

var (
	devMode  = flag.Bool("dev", false, "Enable development mode.")
	logLevel = flag.String("log_level", "info", "Log level.")

	healthProbePort = flag.Int("health_probe_port", 8080, "Port for the health probe.")
	readyProbePort  = flag.Int("ready_probe_port", 8083, "Port for the ready probe.")
	metricsPort     = flag.Int("metrics_port", 8081, "Port for the metrics endpoint.")

	apiServerAddr = flag.String("apiserver_addr", "host.docker.internal:8443", "APIServer address.")
	jwksURLs      = flag.String("jwks_urls", "", "Comma-separated URLs of the JWKS endpoints.")
	localRoute    = flag.String("local_route", "", "Local route for the tunnel.")
)

func main() {
	flag.Parse()
	var lOpts []log.Option
	if *devMode {
		lOpts = append(lOpts, log.WithDevMode(), log.WithAlsoLogToStderr())
	} else if *logLevel != "" {
		lOpts = append(lOpts, log.WithLevelString(*logLevel))
	}
	log.Init(lOpts...)
	ctx := signals.SetupSignalHandler()

	if *apiServerAddr == "" {
		log.Fatalf("--apiserver_addr must be set")
	}
	if *jwksURLs == "" {
		log.Fatalf("--jwks_urls must be set")
	}

	log.Infof("Setting up managers")

	ctrl.SetLogger(zap.New(zap.UseDevMode(true))) // TODO(dilyevsky): Use default golang logger.
	rC := apiserver.NewClientConfig(apiserver.WithClientHost(*apiServerAddr))
	mgr, err := ctrl.NewManager(rC, ctrl.Options{
		Cache: cache.Options{
			SyncPeriod: ptr.To(30 * time.Second),
		},
		Scheme:         scheme,
		LeaderElection: false,
		Metrics: metricsserver.Options{
			BindAddress: fmt.Sprintf(":%d", *metricsPort),
		},
		HealthProbeBindAddress: fmt.Sprintf(":%d", *healthProbePort),
	})
	if err != nil {
		log.Fatalf("Unable to start manager: %v", err)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		log.Fatalf("Failed to add healthz check: %v", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		log.Fatalf("Failed to add readyz check: %v", err)
	}

	g, ctx := errgroup.WithContext(ctx)

	jwtValidator, err := token.NewRemoteValidator(ctx, strings.Split(*jwksURLs, ","))
	if err != nil {
		log.Fatalf("Failed to create JWT validator: %v", err)
	}

	var lr netip.Prefix
	if *localRoute != "" {
		lr, err = netip.ParsePrefix(*localRoute)
		if err != nil {
			log.Fatalf("Failed to parse local route: %v", err)
		}
	} else {
		lr, err = tunnelnet.LocalRouteIPv6()
		if err != nil {
			log.Fatalf("Failed to create local route: %v", err)
		}
	}

	r, err := router.NewNetlinkRouter()
	if err != nil {
		log.Fatalf("Failed to create netlink router: %v", err)
	}

	srv := tunnel.NewTunnelServer(
		mgr.GetClient(),
		jwtValidator,
		r,
		tunnel.WithLocalRoute(lr),
	)
	g.Go(func() error {
		log.Infof("Starting Tunnel Proxy server")

		if err := srv.SetupWithManager(mgr); err != nil {
			log.Fatalf("Unable to setup Tunnel Proxy server: %v", err)
		}

		return srv.Start(ctx)
	})

	g.Go(func() error {
		log.Infof("Starting manager")

		return mgr.Start(ctx)
	})

	if err := g.Wait(); err != nil {
		log.Fatalf("Exited with error: %v", err)
	}
}

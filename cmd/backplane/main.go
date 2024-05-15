package main

import (
	"crypto/tls"
	"flag"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/apoxy-dev/apoxy-cli/internal/apiserver"
	bpctrl "github.com/apoxy-dev/apoxy-cli/internal/backplane/controllers"
	"github.com/apoxy-dev/apoxy-cli/internal/log"

	ctrlv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/controllers/v1alpha1"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(ctrlv1alpha1.AddToScheme(scheme))
}

var (
	projectID = flag.String("project_id", "", "Apoxy project UUID.")
	proxyName = flag.String("proxy_name", "", "Name of the proxy to manage.")

	apiserverHost = flag.String("apiserver_host", "host.docker.internal", "API server address.")

	chAddrs  = flag.String("ch_addrs", "", "Comma-separated list of ClickHouse host:port addresses.")
	chSecure = flag.Bool("ch_secure", false, "Whether to connect to Clickhouse using TLS.")
	chDebug  = flag.Bool("ch_debug", false, "Enables debug prints for ClickHouse client.")
)

func main() {
	flag.Parse()
	projUUID, err := uuid.Parse(*projectID)
	if err != nil {
		log.Fatalf("invalid project UUID: %v", err)
	}
	if *proxyName == "" {
		log.Fatalf("proxy name is required")
	}

	ctx := ctrl.SetupSignalHandler()

	log.Infof("Connecting to ClickHouse at %v", *chAddrs)
	chOpts := &clickhouse.Options{
		Addr: strings.Split(*chAddrs, ","),
		Auth: clickhouse.Auth{
			Database: strings.ReplaceAll(projUUID.String(), "-", ""),
			//Username: strings.ReplaceAll(*projectID, "-", ""),
			//Password: os.Getenv("CH_PASSWORD"),
		},
		DialTimeout: 5 * time.Second,
		Settings: clickhouse.Settings{
			"max_execution_time": 60,
		},
		Debug: *chDebug,
	}
	if *chSecure { // Secure mode requires setting at least empty tls.Config.
		chOpts.TLS = &tls.Config{}
	}
	// TODO(dsky): Wrap this for lazy initialization to avoid blocking startup.
	chConn, err := clickhouse.Open(chOpts)
	if err != nil {
		log.Fatalf("Failed to connect to ClickHouse: %v", err)
	}
	if err := chConn.Ping(ctx); err != nil {
		log.Fatalf("Failed to ping ClickHouse: %v", err)
	}

	rC := apiserver.NewLocalClientConfig(*apiserverHost)
	ctrl.SetLogger(zap.New(zap.UseDevMode(true))) // TODO(dilyevsky): Use default golang logger.
	mgr, err := ctrl.NewManager(rC, ctrl.Options{
		Cache: cache.Options{
			SyncPeriod: pointer.Duration(30 * time.Second),
		},
		Scheme:         scheme,
		LeaderElection: false,
		Metrics: metricsserver.Options{
			BindAddress: ":8081",
		},
	})

	if err != nil {
		log.Fatalf("unable to start manager: %v", err)
	}
	if err := bpctrl.NewProxyReconciler(
		mgr.GetClient(),
		projUUID,
		*proxyName,
		chConn,
	).SetupWithManager(ctx, mgr, *proxyName); err != nil {
		log.Errorf("failed to set up Backplane controller: %v", err)
		return
	}

	if err := mgr.Start(ctx); err != nil {
		log.Fatalf("unable to start manager: %v", err)
	}
}

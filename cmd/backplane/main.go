package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/apoxy-dev/apoxy-cli/internal/apiserver"
	bpctrl "github.com/apoxy-dev/apoxy-cli/internal/backplane/controllers"
	"github.com/apoxy-dev/apoxy-cli/internal/backplane/wasm/ext_proc"
	"github.com/apoxy-dev/apoxy-cli/internal/backplane/wasm/manifest"
	"github.com/apoxy-dev/apoxy-cli/internal/log"

	ctrlv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/controllers/v1alpha1"
	extensionv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/extensions/v1alpha1"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(ctrlv1alpha1.AddToScheme(scheme))
	utilruntime.Must(extensionv1alpha1.AddToScheme(scheme))
}

var (
	projectID   = flag.String("project_id", "", "Apoxy project UUID.")
	proxyName   = flag.String("proxy", "", "Name of the proxy to manage.")
	replicaName = flag.String("replica", "", "Name of the replica to manage.")

	devMode = flag.Bool("dev", false, "Enable development mode.")

	apiserverHost = flag.String("apiserver_host", "host.docker.internal", "APIServer address.")

	chAddrs  = flag.String("ch_addrs", "", "Comma-separated list of ClickHouse host:port addresses.")
	chSecure = flag.Bool("ch_secure", false, "Whether to connect to Clickhouse using TLS.")
	chDebug  = flag.Bool("ch_debug", false, "Enables debug prints for ClickHouse client.")

	wasmExtProcPort = flag.Int("wasm_ext_proc_port", 2020, "Port for the WASM extension processor.")
	wasmStorePort   = flag.Int("wasm_store_port", 8081, "Port for the remote WASM store.")
	goPluginDir     = flag.String("go_plugin_dir", "/var/lib/apoxy/go", "Directory for Go plugins.")
)

func main() {
	flag.Parse()
	var lOpts []log.Option
	if *devMode {
		lOpts = append(lOpts, log.WithDevMode())
	}
	log.Init(lOpts...)

	projUUID, err := uuid.Parse(*projectID)
	if err != nil {
		log.Fatalf("invalid project UUID: %v", err)
	}
	if *proxyName == "" {
		log.Fatalf("proxy name is required")
	}

	ctx := ctrl.SetupSignalHandler()

	var chConn chdriver.Conn
	if *chAddrs != "" {
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
		var err error
		chConn, err = clickhouse.Open(chOpts)
		if err != nil {
			log.Fatalf("Failed to connect to ClickHouse: %v", err)
		}
		if err := chConn.Ping(ctx); err != nil {
			log.Fatalf("Failed to ping ClickHouse: %v", err)
		}
	}

	log.Infof("Setting up WASM runtime")

	ls, err := net.Listen("tcp", fmt.Sprintf(":%d", *wasmExtProcPort))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer ls.Close()
	srv := grpc.NewServer()
	ms := manifest.NewMemory()
	wasmSrv := ext_proc.NewServer(ms)
	wasmSrv.Register(srv)
	// Stop gracefully on SIGTERM.
	ch := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(ch, syscall.SIGTERM)
	go func() {
		<-ch
		log.Infof("Shutting down WASM runtime server")
		srv.GracefulStop()
		close(done)
	}()
	go func() {
		log.Infof("Starting WASM runtime server on %v", ls.Addr())
		if err := srv.Serve(ls); err != nil {
			log.Fatalf("Failed to start WASM runtime server: %v", err)
		}
	}()

	log.Infof("Setting up managers")

	rC := apiserver.NewClientConfig(apiserver.WithClientHost(*apiserverHost))
	ctrl.SetLogger(zap.New(zap.UseDevMode(true))) // TODO(dilyevsky): Use default golang logger.
	mgr, err := ctrl.NewManager(rC, ctrl.Options{
		Cache: cache.Options{
			SyncPeriod: ptr.To(30 * time.Second),
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

	log.Infof("Setting up controllers")
	if err := bpctrl.NewProxyReconciler(
		mgr.GetClient(),
		*replicaName,
		*apiserverHost,
		bpctrl.WithClickHouseConn(chConn),
	).SetupWithManager(ctx, mgr, *proxyName); err != nil {
		log.Errorf("failed to set up Backplane controller: %v", err)
		return
	}
	if err := bpctrl.NewEdgeFuncReconciler(
		mgr.GetClient(),
		fmt.Sprintf("%s:%d", *apiserverHost, *wasmStorePort),
		ms,
		*goPluginDir,
	).SetupWithManager(ctx, mgr, *proxyName); err != nil {
		log.Errorf("failed to set up EdgeFunction controller: %v", err)
		return
	}

	log.Infof("Starting manager")
	if err := mgr.Start(ctx); err != nil {
		log.Fatalf("unable to start manager: %v", err)
	}
	<-done
}

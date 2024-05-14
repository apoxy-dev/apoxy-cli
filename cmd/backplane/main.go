package main

import (
	"flag"
	"time"

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
	projectID     = flag.String("project_id", "", "Apoxy project UUID.")
	proxyName     = flag.String("proxy_name", "", "Name of the proxy to manage.")
	apiserverHost = flag.String("apiserver_host", "host.docker.internal", "API server address.")
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
	).SetupWithManager(ctx, mgr, *proxyName); err != nil {
		log.Errorf("failed to set up Backplane controller: %v", err)
		return
	}

	if err := mgr.Start(ctx); err != nil {
		log.Fatalf("unable to start manager: %v", err)
	}
}

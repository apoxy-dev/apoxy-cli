package main

import (
	"context"
	"errors"
	"flag"
	"os"
	goruntime "runtime"

	"github.com/google/uuid"
	"github.com/temporalio/cli/temporalcli/devserver"
	tclient "go.temporal.io/sdk/client"
	tworker "go.temporal.io/sdk/worker"
	ctrl "sigs.k8s.io/controller-runtime"

	a3yversionedclient "github.com/apoxy-dev/apoxy-cli/client/versioned"
	"github.com/apoxy-dev/apoxy-cli/internal/apiserver"
	"github.com/apoxy-dev/apoxy-cli/internal/apiserver/ingest"
	"github.com/apoxy-dev/apoxy-cli/internal/gateway"
	"github.com/apoxy-dev/apoxy-cli/internal/log"
)

var (
	devMode = flag.Bool("dev", false, "Enable development mode.")

	dbFilePath      = flag.String("db", "apoxy.db", "Path to the database file.")
	tmprlDBFilePath = flag.String("temporal-db", "temporal.db", "Path to the Temporal database file.")
	inCluster       = flag.Bool("in-cluster", false, "Enable in-cluster authentication.")
	ingestStoreDir  = flag.String("ingest-store-dir", os.TempDir(), "Path to the ingest store directory.")
	ingestStorePort = flag.Int("ingest-store-port", 8081, "Port for the ingest store.")
)

func stopCh(ctx context.Context) <-chan interface{} {
	ch := make(chan interface{})
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch
}

type startErr struct {
	Err error
}

func (r *startErr) Error() string {
	return r.Err.Error()
}

func main() {
	flag.Parse()
	var lOpts []log.Option
	if *devMode {
		lOpts = append(lOpts, log.WithDevMode(), log.WithAlsoLogToStderr())
	}
	log.Init(lOpts...)
	ctx, ctxCancel := context.WithCancelCause(ctrl.SetupSignalHandler())

	tOpts := devserver.StartOptions{
		FrontendIP:             "127.0.0.1",
		FrontendPort:           7223,
		Namespaces:             []string{"default"},
		Logger:                 log.DefaultLogger,
		ClusterID:              uuid.NewString(),
		MasterClusterName:      "active",
		CurrentClusterName:     "active",
		InitialFailoverVersion: 1,
		DatabaseFile:           *tmprlDBFilePath,
	}
	tSrv, err := devserver.Start(tOpts)
	if err != nil {
		log.Fatalf("failed starting Temporal server: %w", err)
	}
	defer tSrv.Stop()
	tc, err := tclient.NewLazyClient(tclient.Options{
		HostPort:  "localhost:7223",
		Namespace: "default",
		Logger:    log.DefaultLogger,
	})
	if err != nil {
		log.Fatalf("failed creating Temporal client: %w", err)
	}

	gwSrv := gateway.NewServer()
	go func() {
		if err := gwSrv.Run(ctx); err != nil {
			log.Errorf("failed to serve Gateway APIs: %v", err)
			ctxCancel(&startErr{Err: err})
		}
	}()

	m := apiserver.New()
	go func() {
		sOpts := []apiserver.Option{
			apiserver.WithSQLitePath(*dbFilePath),
		}
		if *inCluster {
			sOpts = append(sOpts, apiserver.WithInClusterAuth())
		}
		if err := m.Start(ctx, gwSrv, tc, sOpts...); err != nil {
			log.Errorf("failed to start API server: %v", err)
			ctxCancel(&startErr{Err: err})
		}
	}()
	select {
	case err, ok := <-m.ReadyCh:
		if !ok || err == nil {
			log.Infof("API server is ready")
		} else {
			log.Fatalf("API server failed to start: %v", err)
		}
	case <-ctx.Done():
		log.Fatalf("context canceled: %v", context.Cause(ctx))
	}

	a3y, err := a3yversionedclient.NewForConfig(m.ClientConfig())
	if err != nil {
		log.Fatalf("failed creating A3Y client: %v", err)
		ctxCancel(&startErr{Err: err})
	}

	wOpts := tworker.Options{
		MaxConcurrentActivityExecutionSize:     goruntime.NumCPU(),
		MaxConcurrentWorkflowTaskExecutionSize: goruntime.NumCPU(),
		EnableSessionWorker:                    true,
	}
	w := tworker.New(tc, ingest.EdgeFunctionIngestQueue, wOpts)
	ingest.RegisterWorkflows(w)
	ww := ingest.NewWorker(a3y, *ingestStoreDir)
	ww.RegisterActivities(w)
	go func() {
		if err = ww.ListenAndServeEdgeFuncs("" /* host */, *ingestStorePort); err != nil {
			log.Errorf("failed to start Wasm server: %v", err)
			ctxCancel(&startErr{Err: err})
		}
	}()
	go func() {
		err = w.Run(stopCh(ctx))
		if err != nil {
			log.Errorf("failed running Temporal worker: %v", err)
			ctxCancel(&startErr{Err: err})
		}
	}()

	<-ctx.Done()
	sErr := &startErr{}
	if err := context.Cause(ctx); errors.As(err, &sErr) {
		log.Errorf("failed to start: %v", sErr.Err)
	} else {
		log.Infof("shutting down")
	}
}

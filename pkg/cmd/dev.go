package cmd

import (
	"context"
	goerrors "errors"
	"fmt"
	"log/slog"
	"os"
	goruntime "runtime"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/temporalio/cli/temporalcli/devserver"
	tclient "go.temporal.io/sdk/client"
	tworker "go.temporal.io/sdk/worker"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/discovery"
	memory "k8s.io/client-go/discovery/cached"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/restmapper"

	"github.com/apoxy-dev/apoxy-cli/config"
	"github.com/apoxy-dev/apoxy-cli/pkg/apiserver"
	"github.com/apoxy-dev/apoxy-cli/pkg/apiserver/ingest"
	bpdrivers "github.com/apoxy-dev/apoxy-cli/pkg/backplane/drivers"
	"github.com/apoxy-dev/apoxy-cli/pkg/backplane/portforward"
	chdrivers "github.com/apoxy-dev/apoxy-cli/pkg/clickhouse/drivers"
	"github.com/apoxy-dev/apoxy-cli/pkg/gateway"
	"github.com/apoxy-dev/apoxy-cli/pkg/log"

	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
)

var (
	rs           = runtime.NewScheme()
	codecFactory = serializer.NewCodecFactory(rs)
	decodeFn     = codecFactory.UniversalDeserializer().Decode
)

func init() {
	utilruntime.Must(corev1alpha.Install(rs))

	rootCmd.AddCommand(devCmd)
}

func maybeNamespaced(un *unstructured.Unstructured) string {
	ns := un.GetNamespace()
	if ns == "" {
		return un.GetName()
	}
	return fmt.Sprintf("%s/%s", ns, un.GetName())
}

func updateFromFile(ctx context.Context, proxyNameOverride, path string) error {
	cfg, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	c, err := config.DefaultAPIClient()
	if err != nil {
		return err
	}

	dc, err := discovery.NewDiscoveryClientForConfig(c.RESTConfig)
	if err != nil {
		return err
	}
	dynClient, err := dynamic.NewForConfig(c.RESTConfig)
	if err != nil {
		return err
	}
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(dc))

	for _, objYaml := range strings.Split(string(cfg), "\n---\n") {
		unObj := &unstructured.Unstructured{}
		_, _, err := decodeFn([]byte(objYaml), nil, unObj)
		if err != nil {
			return fmt.Errorf("failed to decode object: %w", err)
		}

		mapping, err := mapper.RESTMapping(
			unObj.GroupVersionKind().GroupKind(),
			unObj.GroupVersionKind().Version,
		)
		if err != nil {
			return err
		}

		log.Debugf("creating object gvk=%v name=%s", unObj.GroupVersionKind(), maybeNamespaced(unObj))

		if unObj.GetKind() == "Proxy" {
			unObj.SetName(proxyNameOverride)
		} else if unObj.GetKind() == "Gateway" {
			// Override .spec.infrastructure.parametersRef.name to proxy name.
			if err := unstructured.SetNestedField(
				unObj.Object,
				proxyNameOverride,
				"spec", "infrastructure", "parametersRef", "name",
			); err != nil {
				return fmt.Errorf("failed to set .spec.infrastructure.parametersRef.name: %w", err)
			}
		}

		_, err = dynClient.Resource(mapping.Resource).
			Namespace(unObj.GetNamespace()).
			Create(ctx, unObj, metav1.CreateOptions{})
		if errors.IsAlreadyExists(err) {
			log.Debugf("object gvk=%v name=%s already exists, updating...", unObj.GroupVersionKind(), maybeNamespaced(unObj))

			res, err := dynClient.Resource(mapping.Resource).
				Namespace(unObj.GetNamespace()).
				Get(ctx, unObj.GetName(), metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("failed to get object gvk=%v name=%s: %w", unObj.GroupVersionKind(), maybeNamespaced(unObj), err)
			}

			unObj.SetResourceVersion(res.GetResourceVersion())

			_, err = dynClient.Resource(mapping.Resource).
				Namespace(unObj.GetNamespace()).
				Update(ctx, unObj, metav1.UpdateOptions{})
			if err != nil {
				return fmt.Errorf("failed to update object gvk=%v name=%s: %w", unObj.GroupVersionKind(), maybeNamespaced(unObj), err)
			}

			log.Debugf("updated %v object %s\n", unObj.GroupVersionKind(), maybeNamespaced(unObj))
		} else if err != nil {
			return fmt.Errorf("failed to create object gvk=%v name=%s: %w", unObj.GroupVersionKind(), maybeNamespaced(unObj), err)
		} else {
			log.Debugf("created object gvk=%v name=%s\n", unObj.GroupVersionKind(), maybeNamespaced(unObj))
		}
	}
	return err
}

// watchAndReloadConfig watches the given file for changes and reloads the
// Apoxy configuration when the file changes.
// Proxy object name will be overridden with the given value.
func watchAndReloadConfig(ctx context.Context, proxyNameOverride, path string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()
	if err := watcher.Add(path); err != nil {
		return err
	}

	if err := updateFromFile(ctx, proxyNameOverride, path); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if !ev.Has(fsnotify.Write) {
				continue
			}

			// Reload the proxy configuration
			if err := updateFromFile(ctx, proxyNameOverride, path); err != nil {
				return err
			}
		case <-time.After(3 * time.Second):
			// Reload the proxy configuration
			if err := updateFromFile(ctx, proxyNameOverride, path); err != nil {
				return err
			}
		case err := <-watcher.Errors:
			return err
		}
	}
	panic("unreachable")
}

type runError struct {
	Err error
}

func (e *runError) Error() string {
	return e.Err.Error()
}

func (e *runError) Unwrap() error {
	return e.Err
}

func stopCh(ctx context.Context) <-chan interface{} {
	ch := make(chan interface{})
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch
}

var devCmd = &cobra.Command{
	Use:   "dev [path/to/proxy.yaml]",
	Short: "Develop against the Apoxy API locally",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		config.LocalMode = true // Enable local mode
		cmd.SilenceUsage = true
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		projectID := uuid.New()
		if cfg.CurrentProject != uuid.Nil {
			projectID = cfg.CurrentProject
		}

		path := args[0]
		proxyName, err := os.Hostname()
		if err != nil {
			return err
		}

		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}

		fmt.Printf("Starting Apoxy server with Proxy name=%s ...\n", proxyName)

		ctx, ctxCancel := context.WithCancelCause(cmd.Context())

		tOpts := devserver.StartOptions{
			FrontendIP:             "127.0.0.1",
			FrontendPort:           7223,
			Namespaces:             []string{"default"},
			Logger:                 log.DefaultLogger,
			LogLevel:               slog.LevelError, // Too noisy otherwise.
			ClusterID:              uuid.NewString(),
			MasterClusterName:      "active",
			CurrentClusterName:     "active",
			InitialFailoverVersion: 1,
		}
		tSrv, err := devserver.Start(tOpts)
		if err != nil {
			return fmt.Errorf("failed starting Temporal server: %w", err)
		}
		defer tSrv.Stop()
		tc, err := tclient.NewLazyClient(tclient.Options{
			HostPort:  "localhost:7223",
			Namespace: "default",
			Logger:    nil,
		})
		if err != nil {
			return fmt.Errorf("failed creating Temporal client: %w", err)
		}

		wOpts := tworker.Options{
			MaxConcurrentActivityExecutionSize:     goruntime.NumCPU(),
			MaxConcurrentWorkflowTaskExecutionSize: goruntime.NumCPU(),
			EnableSessionWorker:                    true,
		}
		w := tworker.New(tc, ingest.EdgeFunctionIngestQueue, wOpts)
		ingest.RegisterWorkflows(w)
		ww := ingest.NewWorker(nil /* no k8s client in local mode */, c, os.Getenv("TMPDIR"))
		ww.RegisterActivities(w)
		go func() {
			if err = ww.ListenAndServeEdgeFuncs("localhost", 8081); err != nil {
				log.Errorf("failed to start Wasm server: %v", err)
				ctxCancel(&runError{Err: err})
			}
		}()
		go func() {
			err = w.Run(stopCh(ctx))
			if err != nil {
				log.Errorf("failed running Temporal worker: %v", err)
				ctxCancel(&runError{Err: err})
			}
		}()

		gwSrv := gateway.NewServer()
		go func() {
			if err := gwSrv.Run(ctx); err != nil {
				log.Errorf("failed to serve Gateway APIs: %v", err)
				ctxCancel(&runError{Err: err})
			}
		}()

		m := apiserver.New()
		go func() {
			if err := m.Start(ctx, gwSrv, tc, apiserver.WithInMemorySQLite()); err != nil {
				log.Errorf("failed to start API server: %v", err)
				ctxCancel(&runError{Err: err})
			}
		}()
		select {
		case <-m.ReadyCh:
		case <-ctx.Done():
			return nil
		}

		/*
			rlDriver, err := ratelimitdrivers.GetDriver("docker")
			if err != nil {
				return err
			}
			if err := rlDriver.Start(
				ctx,
				projID,
				fmt.Sprintf("host.docker.internal:%d", apiserverpolicy.XDSPort),
			); err != nil {
				return err
			}
		*/

		chDriver, err := chdrivers.GetDriver("docker")
		if err != nil {
			return err
		}

		if err := chDriver.Start(ctx, projectID); err != nil {
			return err
		}
		chAddr, err := chDriver.GetAddr(ctx)
		if err != nil {
			return err
		}

		bpDriver, err := bpdrivers.GetDriver("docker")
		if err != nil {
			return err
		}
		cname, err := bpDriver.Start(
			ctx,
			projectID,
			proxyName,
			bpdrivers.WithArgs(
				"--ch_addrs", chAddr+":9000",
				"--dev", "true",
			),
		)
		if err != nil {
			return err
		}
		defer bpDriver.Stop(projectID, proxyName)

		rc := apiserver.NewClientConfig()
		fwd, err := portforward.NewPortForwarder(rc, proxyName, proxyName, cname)
		if err != nil {
			return err
		}
		go func() {
			if err := fwd.Run(ctx); err != nil {
				ctxCancel(&runError{Err: err})
			}
			// If err is nil, it means context has been cancelled.
		}()

		fmt.Printf("Watching %s for Proxy configurations...\n", path)

		if err := watchAndReloadConfig(ctx, proxyName, path); err != nil {
			return err
		}
		go func() {
			<-cmd.Context().Done()
			fmt.Printf("\r") // Clear the ^C
			fmt.Printf("Caught interrupt, shutting down...\n")
		}()
		<-ctx.Done()

		var runErr *runError
		if err := context.Cause(ctx); goerrors.As(err, &runErr) {
			return runErr.Err
		}

		return nil
	},
}

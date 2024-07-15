package alpha

import (
	"context"
	goerrors "errors"
	"fmt"
	"os"
	goruntime "runtime"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/temporalio/cli/temporalcli/devserver"
	tclient "go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
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
	"github.com/apoxy-dev/apoxy-cli/internal/apiserver"
	apiserverctrl "github.com/apoxy-dev/apoxy-cli/internal/apiserver/controllers"
	apiserverext "github.com/apoxy-dev/apoxy-cli/internal/apiserver/extensions"
	"github.com/apoxy-dev/apoxy-cli/internal/apiserver/ingest"
	apiserverpolicy "github.com/apoxy-dev/apoxy-cli/internal/apiserver/policy"
	bpdrivers "github.com/apoxy-dev/apoxy-cli/internal/backplane/drivers"
	"github.com/apoxy-dev/apoxy-cli/internal/backplane/portforward"
	chdrivers "github.com/apoxy-dev/apoxy-cli/internal/clickhouse/drivers"
	"github.com/apoxy-dev/apoxy-cli/internal/gateway"
	"github.com/apoxy-dev/apoxy-cli/internal/log"

	ctrlv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/controllers/v1alpha1"
	extensionsv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/extensions/v1alpha1"
	policyv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/policy/v1alpha1"
)

var (
	scheme   = runtime.NewScheme()
	codecs   = serializer.NewCodecFactory(scheme)
	decodeFn = codecs.UniversalDeserializer().Decode
)

func init() {
	utilruntime.Must(ctrlv1alpha1.AddToScheme(scheme))
	utilruntime.Must(policyv1alpha1.AddToScheme(scheme))
	utilruntime.Must(extensionsv1alpha1.AddToScheme(scheme))
}

func maybeNamespaced(un *unstructured.Unstructured) string {
	ns := un.GetNamespace()
	if ns == "" {
		return un.GetName()
	}
	return fmt.Sprintf("%s/%s", ns, un.GetName())
}

func updateFromFile(ctx context.Context, path string) error {
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

		_, err = dynClient.Resource(mapping.Resource).
			Namespace(unObj.GetNamespace()).
			Create(ctx, unObj, metav1.CreateOptions{})
		if errors.IsAlreadyExists(err) {
			log.Debugf("object %v %s already exists, updating...", unObj.GroupVersionKind(), maybeNamespaced(unObj))

			_, err = dynClient.Resource(mapping.Resource).
				Namespace(unObj.GetNamespace()).
				Update(ctx, unObj, metav1.UpdateOptions{})
			if err != nil {
				return fmt.Errorf("failed to update object %s: %w", maybeNamespaced(unObj), err)
			}

			fmt.Printf("updated %v object %s\n", unObj.GroupVersionKind(), maybeNamespaced(unObj))
		} else if err != nil {
			return fmt.Errorf("failed to create object %s: %w", maybeNamespaced(unObj), err)
		} else {
			fmt.Printf("created %v object %s\n", unObj.GroupVersionKind(), maybeNamespaced(unObj))
		}
	}
	return err
}

// watchAndReloadConfig watches the given file for changes and reloads the
// Apoxy configuration when the file changes.
func watchAndReloadConfig(ctx context.Context, path string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()
	if err := watcher.Add(path); err != nil {
		return err
	}

	if err := updateFromFile(ctx, path); err != nil {
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
			if err := updateFromFile(ctx, path); err != nil {
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

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run Apoxy server locally",
	Long: `Run Apoxy API locally. This command brings up Apoxy API stack locally
allowing you to test and develop your proxy infrastructure.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		config.LocalMode = true // Enable local mode
		cmd.SilenceUsage = true
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		projID := uuid.New()
		if cfg.ProjectID.String() != "" {
			projID = cfg.ProjectID
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

		fmt.Printf("Starting Apoxy server with proxy %s...\n", proxyName)

		ctx, ctxCancel := context.WithCancelCause(cmd.Context())

		tOpts := devserver.StartOptions{
			FrontendIP:             "127.0.0.1",
			FrontendPort:           7223,
			Namespaces:             []string{"default"},
			Logger:                 log.DefaultLogger,
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
		})
		if err != nil {
			return fmt.Errorf("failed creating Temporal client: %w", err)
		}

		wOpts := tworker.Options{
			MaxConcurrentActivityExecutionSize:     goruntime.NumCPU(),
			MaxConcurrentWorkflowTaskExecutionSize: goruntime.NumCPU(),
			EnableSessionWorker:                    true,
		}
		w := worker.New(tc, ingest.EdgeFunctionIngestQueue, wOpts)
		ingest.RegisterWorkflows(w)
		ww := ingest.NewWorker(c, os.Getenv("TMPDIR"))
		ww.RegisterActivities(w)
		/*
			go func() {
				if err = ww.ListenAndServeWasm("localhost", 8081); err != nil {
					log.Errorf("failed to start Wasm server: %v", err)
					ctxCancel(&runError{Err: err})
				}
			}()
			go func() {
				err = w.Run(stopCh(cmd.Context()))
				if err != nil {
					log.Errorf("failed running Temporal worker: %v", err)
					ctxCancel(&runError{Err: err})
				}
			}()
		*/

		startCh := make(chan error)
		go func() {
			mgr, err := apiserver.Start(cmd.Context(), apiserver.WithSQLitePath("file::memory:?cache=shared"))
			if err != nil {
				log.Errorf("failed to start API server: %v", err)
				startCh <- err
				return
			}
			startCh <- nil

			if err := apiserverctrl.NewProxyReconciler(
				mgr.GetClient(),
			).SetupWithManager(cmd.Context(), mgr); err != nil {
				log.Errorf("failed to set up Project controller: %v", err)
				return
			}
			if err := (&ctrlv1alpha1.Proxy{}).SetupWebhookWithManager(mgr); err != nil {
				log.Errorf("failed to set up Proxy webhook: %v", err)
				return
			}

			if err := apiserverext.NewEdgeFuncReconciler(
				mgr.GetClient(),
				tc,
			).SetupWithManager(cmd.Context(), mgr); err != nil {
				log.Errorf("failed to set up Project controller: %v", err)
				return
			}
			if err := (&extensionsv1alpha1.EdgeFunction{}).SetupWebhookWithManager(mgr); err != nil {
				log.Errorf("failed to set up EdgeFunction webhook: %v", err)
				return
			}

			pr := apiserverpolicy.NewRateLimitReconciler(
				cmd.Context(),
				mgr.GetClient(),
				projID,
			)
			if err := pr.SetupWithManager(cmd.Context(), mgr); err != nil {
				log.Errorf("failed to set up RateLimit controller: %v", err)
				return
			}
			go func() {
				if err := pr.ServeXDS(); err != nil {
					log.Errorf("failed to serve XDS: %v", err)
					ctxCancel(&runError{Err: err})
				}
			}()

			go func() {
				if err := gateway.Serve(cmd.Context()); err != nil {
					log.Errorf("failed to serve Gateway APIs: %v", err)
					ctxCancel(&runError{Err: err})
				}
			}()

			if err := mgr.Start(cmd.Context()); err != nil {
				log.Errorf("failed to start manager: %v", err)
			}
		}()
		select {
		case err := <-startCh:
			if err != nil {
				return err
			}
		case <-cmd.Context().Done():
			return nil
		}

		/*
			rlDriver, err := ratelimitdrivers.GetDriver("docker")
			if err != nil {
				return err
			}
			if err := rlDriver.Start(
				cmd.Context(),
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
		if err := chDriver.Start(cmd.Context(), projID); err != nil {
			return err
		}
		chAddr, err := chDriver.GetAddr(cmd.Context())
		if err != nil {
			return err
		}

		bpDriver, err := bpdrivers.GetDriver("docker")
		if err != nil {
			return err
		}
		cname, err := bpDriver.Start(
			cmd.Context(),
			projID,
			proxyName,
			bpdrivers.WithArgs(
				"--ch_addrs", chAddr+":9000",
				"--dev", "true",
			),
		)
		if err != nil {
			return err
		}

		fmt.Printf("Proxy is running at %s. Watching %s for changes...\n", cname, path)

		rc := apiserver.NewLocalClientConfig("localhost")
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

		if err := watchAndReloadConfig(cmd.Context(), path); err != nil {
			return err
		}
		<-cmd.Context().Done()

		var runErr *runError
		if err := context.Cause(ctx); goerrors.As(err, &runErr) {
			return runErr.Err
		}

		return nil
	},
}

func init() {
	alphaCmd.AddCommand(runCmd)
}

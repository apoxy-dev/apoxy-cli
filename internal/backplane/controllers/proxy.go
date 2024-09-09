package controllers

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	goerrors "errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	bootstrapv3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/yaml"

	"github.com/apoxy-dev/apoxy-cli/internal/backplane/envoy"
	"github.com/apoxy-dev/apoxy-cli/internal/backplane/logs"
	"github.com/apoxy-dev/apoxy-cli/internal/gateway/xds/bootstrap"
	alog "github.com/apoxy-dev/apoxy-cli/internal/log"

	ctrlv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/controllers/v1alpha1"
)

const (
	proxyReplicaPendingTimeout = 5 * time.Minute
)

var _ reconcile.Reconciler = &ProxyReconciler{}

// ProxyReconciler reconciles a Proxy object.
type ProxyReconciler struct {
	client.Client
	envoy.Runtime

	proxyName     string
	replicaName   string
	apiServerAddr string

	options *options
}

type options struct {
	chConn                   clickhouse.Conn
	apiServerTLSClientConfig *tls.Config
	goPluginDir              string
	releaseURL               string
	useEnvoyContrib          bool
}

// Option is a functional option for ProxyReconciler.
type Option func(*options)

// WithClickHouseConn sets the ClickHouse connection for the ProxyReconciler.
// If not set, log shipping will be disabled.
func WithClickHouseConn(chConn clickhouse.Conn) Option {
	return func(o *options) {
		o.chConn = chConn
	}
}

// WithAPIServerTLSClientConfig sets the TLS client configuration for the API server.
// If not set, the client will use an insecure connection.
func WithAPIServerTLSClientConfig(tlsConfig *tls.Config) Option {
	return func(o *options) {
		o.apiServerTLSClientConfig = tlsConfig
	}
}

// WithGoPluginDir sets the directory for Go plugins.
func WithGoPluginDir(dir string) Option {
	return func(o *options) {
		o.goPluginDir = dir
	}
}

// WithURLRelease enables the use of URL release. (Default is GitHub release).
func WithURLRelease(url string) Option {
	return func(o *options) {
		o.releaseURL = url
	}
}

// WithEnvoyContrib enables the use of Envoy contrib filters.
func WithEnvoyContrib() Option {
	return func(o *options) {
		o.useEnvoyContrib = true
	}
}

func defaultOptions() *options {
	return &options{}
}

// NewProxyReconciler returns a new reconcile.Reconciler implementation for the Proxy resource.
func NewProxyReconciler(
	c client.Client,
	proxyName string,
	replicaName string,
	apiServerAddr string,
	opts ...Option,
) *ProxyReconciler {
	sOpts := defaultOptions()
	for _, opt := range opts {
		opt(sOpts)
	}
	return &ProxyReconciler{
		Client:        c,
		proxyName:     proxyName,
		replicaName:   replicaName,
		apiServerAddr: apiServerAddr,
		options:       sOpts,
	}
}

func findReplicaStatus(p *ctrlv1alpha1.Proxy, rname string) (*ctrlv1alpha1.ProxyReplicaStatus, bool) {
	for i := range p.Status.Replicas {
		if p.Status.Replicas[i].Name == rname {
			return p.Status.Replicas[i], true
		}
	}
	return nil, false
}

func nodeID(p *ctrlv1alpha1.Proxy) string {
	configSHA := sha256.Sum256([]byte(p.Spec.Config))
	return fmt.Sprintf("%s-%x", p.Name, configSHA[:8])
}

func adminUDSPath(nodeID string) string {
	return fmt.Sprintf("/tmp/admin_%s.sock", nodeID)
}

func validateBootstrapConfig(nodeID, config string) (string, error) {
	pb := &bootstrapv3.Bootstrap{}
	if config == "" {
		return "", goerrors.New("bootstrap config is empty")
	}
	jsonBytes, err := yaml.YAMLToJSON([]byte(config))
	if err != nil {
		return "", fmt.Errorf("failed to convert YAML to JSON: %v", err)
	}
	if err := protojson.Unmarshal(jsonBytes, pb); err != nil {
		return "", fmt.Errorf("failed to unmarshal Envoy bootstrap config: %v", err)
	}
	if err := pb.ValidateAll(); err != nil {
		return "", fmt.Errorf("invalid Envoy bootstrap config: %v", err)
	}

	if pb.Node == nil {
		pb.Node = &corev3.Node{}
	}
	pb.Node.Id = nodeID

	pb.Admin = &bootstrapv3.Admin{
		AccessLogPath: "/dev/null",
		Address: &corev3.Address{
			Address: &corev3.Address_Pipe{
				Pipe: &corev3.Pipe{
					Path: adminUDSPath(nodeID),
				},
			},
		},
	}

	cfgBytes, err := protojson.Marshal(pb)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Envoy bootstrap config: %v", err)
	}
	return string(cfgBytes), nil
}

type listenerStatus struct {
	Name         string `json:"name"`
	LocalAddress struct {
		SocketAddress struct {
			Address   string `json:"address"`
			PortValue uint32 `json:"port_value"`
		} `json:"socket_address"`
	} `json:"local_address"`
}

type listeners struct {
	ListenerStatuses []listenerStatus `json:"listener_statuses"`
}

func (r *ProxyReconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	p := &ctrlv1alpha1.Proxy{}
	err := r.Get(ctx, request.NamespacedName, p)
	if errors.IsNotFound(err) {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get Proxy: %w", err)
	}

	log := log.FromContext(ctx, "app", string(p.UID), "name", p.Name, "replica", r.replicaName)
	log.Info("Reconciling Proxy")

	rStatus, found := findReplicaStatus(p, r.replicaName)
	if !found {
		log.Info("Replica not found, creating new one")
		p.Status.Replicas = append(p.Status.Replicas, &ctrlv1alpha1.ProxyReplicaStatus{
			Name:      r.replicaName,
			CreatedAt: metav1.Now(),
			Phase:     ctrlv1alpha1.ProxyReplicaPhasePending,
			Reason:    "Created by Backplane",
		})

		if err := r.Status().Update(ctx, p); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update Proxy status: %w", err)
		}
		return reconcile.Result{}, nil
	}
	ps := r.RuntimeStatus()

	if !p.ObjectMeta.DeletionTimestamp.IsZero() { // The object is being deleted
		log.Info("Proxy is being deleted")

		// If state was terminating and proxy is not running, we can set status to stopped
		// at which point the main proxy controller will delete the proxy.
		if ps.Running {
			switch rStatus.Phase {
			case ctrlv1alpha1.ProxyReplicaPhaseRunning:
				log.Info("Deleting Proxy")
				if err := r.Runtime.Shutdown(ctx); err != nil {
					return reconcile.Result{}, fmt.Errorf("failed to shutdown proxy: %w", err)
				}
				rStatus.Phase = ctrlv1alpha1.ProxyReplicaPhaseTerminating
				rStatus.Reason = "Proxy is being deleted"
			case ctrlv1alpha1.ProxyReplicaPhaseTerminating:
				log.Info("Proxy is terminating")
			case ctrlv1alpha1.ProxyReplicaPhaseStopped, ctrlv1alpha1.ProxyReplicaPhaseFailed:
				log.Error(nil, "Proxy process is running but status is stopped or failed", "phase", rStatus.Phase)
			}
		} else {
			rStatus.Phase = ctrlv1alpha1.ProxyReplicaPhaseStopped
			rStatus.Reason = fmt.Sprintf("Proxy replica exited: %v", ps.ProcState)
		}

		if err := r.Status().Update(ctx, p); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update Proxy: %w", err)
		}

		return ctrl.Result{}, nil // Deleted.
	}

	var requeueAfter time.Duration
	if ps.StartedAt.IsZero() {
		switch rStatus.Phase {
		case ctrlv1alpha1.ProxyReplicaPhasePending:
			log.Info("Starting Proxy")
		case ctrlv1alpha1.ProxyReplicaPhaseRunning:
			rStatus.Phase = ctrlv1alpha1.ProxyReplicaPhaseFailed
			rStatus.Reason = "Replica is in running state but proxy process is not running"
			goto UpdateStatus
		case ctrlv1alpha1.ProxyReplicaPhaseTerminating:
			log.Info("Proxy is terminating")
			rStatus.Phase = ctrlv1alpha1.ProxyReplicaPhaseStopped
			rStatus.Reason = "Proxy terminated"
			goto UpdateStatus
		case ctrlv1alpha1.ProxyReplicaPhaseStopped:
			goto UpdateStatus
		case ctrlv1alpha1.ProxyReplicaPhaseFailed:
			goto UpdateStatus
		default:
			log.Error(nil, "Unexpected phase", "phase", rStatus.Phase)
			rStatus.Phase = ctrlv1alpha1.ProxyReplicaPhaseFailed
			rStatus.Reason = "Unexpected phase"
			goto UpdateStatus
		}

		var (
			cfg string
			err error
		)
		if p.Spec.Config != "" {
			cfg, err = validateBootstrapConfig(nodeID(p), p.Spec.Config)
		} else {
			cfg, err = bootstrap.GetRenderedBootstrapConfig(
				bootstrap.WithXdsServerHost(r.apiServerAddr),
				// TODO(dilyevsky): Add TLS config from r.options.apiServerTLSConfig.
			)
		}
		if err != nil {
			// If the config is invalid, we can't start the proxy.
			log.Error(err, "failed to validate proxy config")
			rStatus.Phase = ctrlv1alpha1.ProxyReplicaPhaseFailed
			rStatus.Reason = fmt.Sprintf("failed to validate proxy config: %v", err)

			if err := r.Status().Update(ctx, p); err != nil {
				return reconcile.Result{}, fmt.Errorf("failed to update proxy status: %w", err)
			}

			return reconcile.Result{}, nil // Leave the proxy in failed state.
		}

		// TODO(dilyevsky): Pass these values from the Proxy object.
		opts := []envoy.Option{
			envoy.WithBootstrapConfigYAML(cfg),
			envoy.WithCluster(p.Name),
			envoy.WithGoPluginDir(r.options.goPluginDir),
			envoy.WithDrainTimeout(&p.Spec.DrainTimeout.Duration),
			envoy.WithAdminHost(bootstrap.EnvoyAdminAddress + ":" + strconv.Itoa(bootstrap.EnvoyAdminPort)),
		}
		if r.options.releaseURL != "" {
			opts = append(opts, envoy.WithRelease(&envoy.URLRelease{
				URL: r.options.releaseURL,
			}))
		} else {
			opts = append(opts, envoy.WithRelease(&envoy.GitHubRelease{
				Contrib: r.options.useEnvoyContrib,
			}))
		}

		if r.options.chConn != nil {
			pUUID, _ := uuid.Parse(string(p.UID))
			lc := logs.NewClickHouseLogsCollector(r.options.chConn, pUUID)
			opts = append(opts, envoy.WithLogsCollector(lc))
		}

		if err := r.Start(ctx, opts...); err != nil {
			if fatalErr, ok := err.(envoy.FatalError); ok {
				rStatus.Phase = ctrlv1alpha1.ProxyReplicaPhaseFailed
				rStatus.Reason = fmt.Sprintf("failed to create proxy replica: %v", fatalErr)
				if err := r.Status().Update(ctx, p); err != nil {
					return reconcile.Result{}, fmt.Errorf("failed to update proxy status: %w", err)
				}

				return reconcile.Result{}, nil // Leave the proxy in failed state.
			}

			return reconcile.Result{}, fmt.Errorf("failed to create proxy: %w", err)
		}

		log.Info("Started Envoy")

		rStatus.Phase = ctrlv1alpha1.ProxyReplicaPhasePending
		rStatus.Reason = "Proxy replica is being created"
		if err := r.Status().Update(ctx, p); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update proxy replica status: %w", err)
		}

		// Requeue after a short delay to check the status of the proxy.
		return reconcile.Result{RequeueAfter: 2 * time.Second}, nil
	}

	if ps.Running {
		switch rStatus.Phase {
		case ctrlv1alpha1.ProxyReplicaPhasePending:
			log.Info("Proxy is running", "start_time", ps.StartedAt)
			rStatus.Phase = ctrlv1alpha1.ProxyReplicaPhaseRunning
			rStatus.Reason = "Running"
		case ctrlv1alpha1.ProxyReplicaPhaseTerminating:
			if err := r.Runtime.Shutdown(ctx); err != nil {
				rStatus.Reason = fmt.Sprintf("Failed to shutdown proxy: %v", err)
			}
		case ctrlv1alpha1.ProxyReplicaPhaseStopped:
			// Replica is stopped but the process still running.
			log.Info("Proxy is stopped but process is still running")
			rStatus.Phase = ctrlv1alpha1.ProxyReplicaPhaseFailed
			rStatus.Reason = "Proxy is stopped but process is still running"
		case ctrlv1alpha1.ProxyReplicaPhaseFailed:
			// Replica is failed but the process still running.
			log.Info("Proxy is failed but process is still running")
			rStatus.Reason = "Proxy is failed but process is still running"
		case ctrlv1alpha1.ProxyReplicaPhaseRunning: // Do nothing.
		}
	} else {
		switch rStatus.Phase {
		case ctrlv1alpha1.ProxyReplicaPhasePending:
			if time.Now().After(rStatus.CreatedAt.Time.Add(proxyReplicaPendingTimeout)) {
				log.Error(nil, "Proxy replica failed to start in time", "timeout", proxyReplicaPendingTimeout, "start_time", ps.StartedAt)
				rStatus.Phase = ctrlv1alpha1.ProxyReplicaPhaseFailed
				rStatus.Reason = "Proxy replica failed to start"
			} else {
				rStatus.Phase = ctrlv1alpha1.ProxyReplicaPhasePending
				rStatus.Reason = "Proxy replica is being created"
				requeueAfter = 2 * time.Second
			}
		case ctrlv1alpha1.ProxyReplicaPhaseRunning:
			rStatus.Phase = ctrlv1alpha1.ProxyReplicaPhaseFailed
			rStatus.Reason = fmt.Sprintf("Proxy replica exited: %v", ps.ProcState)
		case ctrlv1alpha1.ProxyReplicaPhaseTerminating:
			rStatus.Phase = ctrlv1alpha1.ProxyReplicaPhaseStopped
			rStatus.Reason = "Proxy replica stopped"
		case ctrlv1alpha1.ProxyReplicaPhaseFailed, ctrlv1alpha1.ProxyReplicaPhaseStopped: // Do nothing.
		default:
			return reconcile.Result{}, fmt.Errorf("unknown proxy replica phase: %v", rStatus.Phase)
		}
	}

UpdateStatus:
	if err := r.Status().Update(ctx, p); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to update proxy replica status: %w", err)
	}

	return reconcile.Result{RequeueAfter: requeueAfter}, nil
}

func namePredicate(name string) predicate.Funcs {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		if obj == nil {
			return false
		}

		p, ok := obj.(*ctrlv1alpha1.Proxy)
		if !ok {
			return false
		}

		return name == p.Name
	})
}

func (r *ProxyReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	err := mgr.GetFieldIndexer().IndexField(ctx, &ctrlv1alpha1.Proxy{}, "metadata.name", func(rawObj client.Object) []string {
		p := rawObj.(*ctrlv1alpha1.Proxy)
		return []string{p.Name}
	})
	if err != nil {
		return fmt.Errorf("failed to set up field indexer: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&ctrlv1alpha1.Proxy{},
			builder.WithPredicates(
				&predicate.ResourceVersionChangedPredicate{},
				namePredicate(r.proxyName),
			),
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
			RecoverPanic:            ptr.To(true),
		}).
		Complete(r)
}

func (r *ProxyReconciler) Shutdown(ctx context.Context, reason string) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if err := r.Runtime.Shutdown(ctx); err != nil {
			alog.Warnf("Failed to shutdown proxy: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			p := &ctrlv1alpha1.Proxy{}
			err := r.Get(ctx, types.NamespacedName{Name: r.proxyName}, p)
			if errors.IsNotFound(err) {
				alog.Infof("Proxy not found")
				return nil
			}
			if err != nil {
				alog.Errorf("Failed to get proxy: %v", err)
				return err
			}

			rStatus, found := findReplicaStatus(p, r.replicaName)
			if !found {
				alog.Infof("Proxy replica not found")
				return nil
			}

			rStatus.Phase = ctrlv1alpha1.ProxyReplicaPhaseTerminating
			rStatus.Reason = fmt.Sprintf("Proxy replica is being terminated (%s)", reason)

			if err := r.Status().Update(ctx, p); err != nil {
				alog.Errorf("Failed to update proxy replica status: %v", err)
				return err
			}

			return nil
		}); err != nil {
			alog.Errorf("Failed to update proxy replica status: %v", err)
		}
	}()

	wg.Wait()
}

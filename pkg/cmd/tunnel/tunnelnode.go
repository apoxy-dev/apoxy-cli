package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/apoxy-dev/apoxy-cli/client/versioned"
	"github.com/apoxy-dev/apoxy-cli/config"

	configv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/config/v1alpha1"
	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
)

const (
	matchingTunnelNodesIndex = "remoteTunnelNodeIndex"

	tunnelNodeEpochLabel = "core.apoxy.dev/tunnelnode-epoch"
)

var (
	scheme       = runtime.NewScheme()
	codecFactory = serializer.NewCodecFactory(scheme)
	decodeFn     = codecFactory.UniversalDeserializer().Decode
)

func init() {
	utilruntime.Must(corev1alpha.Install(scheme))
}

var tunnelRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a tunnel",
	Long:  "Create a secure tunnel to the remote Apoxy Edge fabric.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		cmd.SilenceUsage = true

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("unable to load config: %w", err)
		}

		a3y, err := config.DefaultAPIClient()
		if err != nil {
			return fmt.Errorf("unable to create API client: %w", err)
		}

		tunnelNodeName := args[0]
		tn, err := a3y.CoreV1alpha().TunnelNodes().Get(ctx, tunnelNodeName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("unable to get TunnelNode: %w", err)
		}

		tun := &tunnelNodeReconciler{
			scheme: scheme,
			cfg:    cfg,
			a3y:    a3y,
		}
		return tun.run(ctx, tn)
	},
}

type tunnelNodeReconciler struct {
	client.Client

	mu              sync.RWMutex
	localTunnelNode corev1alpha.TunnelNode

	scheme *runtime.Scheme
	cfg    *configv1alpha1.Config
	a3y    versioned.Interface
}

func (t *tunnelNodeReconciler) run(ctx context.Context, tn *corev1alpha.TunnelNode) error {
	var err error

	slog.Debug("Running TunnelNode controller", slog.String("name", tn.Name))

	client, err := config.DefaultAPIClient()
	if err != nil {
		return fmt.Errorf("unable to create API client: %w", err)
	}

	mgr, err := ctrl.NewManager(client.RESTConfig, ctrl.Options{
		Scheme:         scheme,
		LeaderElection: false,
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
	})
	if err != nil {
		return fmt.Errorf("unable to set up overall controller manager: %w", err)
	}

	t.Client = mgr.GetClient()
	if err := t.setupWithManager(ctx, mgr, tn.Name); err != nil {
		return fmt.Errorf("unable to set up controller: %w", err)
	}

	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		if err := mgr.Start(ctx); err != nil {
			slog.Error("Manager exited non-zero", slog.Any("error", err))
		}
	}()

	// Set the initial status of the TunnelNode object.
	// Wait for the TunnelNode object to be deleted, or for the command to be cancelled.
	select {
	case <-doneCh:
	case <-ctx.Done():
	}

	return nil
}

func targetRefPredicate(tunnelNodeName string) predicate.Funcs {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		if obj == nil {
			return false
		}
		return obj.GetName() == tunnelNodeName
	})
}

func (t *tunnelNodeReconciler) setupWithManager(
	ctx context.Context,
	mgr ctrl.Manager,
	tunnelNodeName string,
) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(
			&corev1alpha.TunnelNode{},
			builder.WithPredicates(
				predicate.GenerationChangedPredicate{},
				targetRefPredicate(tunnelNodeName),
			),
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
			RecoverPanic:            ptr.To(true),
		}).
		Complete(t)
}

func (t *tunnelNodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := clog.FromContext(ctx)

	var tunnelNode corev1alpha.TunnelNode
	if err := t.Get(ctx, req.NamespacedName, &tunnelNode); err != nil {
		log.Error(err, "Failed to get TunnelNode")
		return ctrl.Result{}, err
	}

	t.mu.RLock()
	isLocal := tunnelNode.Name == t.localTunnelNode.Name
	log.Info("Reconciling", "isLocal", isLocal, "localTunnelNode", t.localTunnelNode.Name, "remoteTunnelNode", tunnelNode.Name)
	if isLocal { // Local tunnel peer - do nothing.
		t.mu.RUnlock()
		t.mu.Lock()
		t.localTunnelNode = *tunnelNode.DeepCopy()
		t.mu.Unlock()
		return ctrl.Result{}, nil
	}
	defer t.mu.RUnlock()

	return ctrl.Result{}, nil
}

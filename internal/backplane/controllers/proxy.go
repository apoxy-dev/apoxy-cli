package controllers

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/apoxy-dev/apoxy-cli/internal/backplane/envoy"

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

	orgID    uuid.UUID
	proxyUID string
	machName string
}

// NewProxyReconciler returns a new reconcile.Reconciler for Proxy objects.
func NewProxyReconciler(
	c client.Client,
	orgID uuid.UUID,
	proxyUID, machName string,
) *ProxyReconciler {
	return &ProxyReconciler{
		Client:   c,
		orgID:    orgID,
		proxyUID: proxyUID,
		machName: machName,
	}
}

func findStatus(name string, p *ctrlv1alpha1.Proxy) (*ctrlv1alpha1.ProxyReplicaStatus, bool) {
	for i := range p.Status.Replicas {
		if p.Status.Replicas[i].Name == name {
			return p.Status.Replicas[i], true
		}
	}
	return nil, false
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

	log := log.FromContext(ctx, "app", string(p.UID), "name", p.Name, "machine", r.machName)
	log.Info("Reconciling Proxy")

	status, found := findStatus(r.machName, p)
	if !found {
		return reconcile.Result{}, fmt.Errorf("failed to find status for machine %q", r.machName)
	}
	ps := r.RuntimeStatus()

	if !p.ObjectMeta.DeletionTimestamp.IsZero() { // The object is being deleted
		log.Info("Proxy is being deleted")

		// If state was terminating and proxy is not running, we can set status to stopped
		// at which point the main proxy controller will delete the proxy.
		if ps.Running {
			switch status.Phase {
			case ctrlv1alpha1.ProxyReplicaPhaseRunning:
				log.Info("Deleting Proxy")
				if err := r.Stop(); err != nil {
					return reconcile.Result{}, fmt.Errorf("failed to shutdown proxy: %w", err)
				}
				status.Phase = ctrlv1alpha1.ProxyReplicaPhaseTerminating
				status.Reason = "Proxy is being deleted"
			case ctrlv1alpha1.ProxyReplicaPhaseTerminating:
				log.Info("Proxy is terminating")
			case ctrlv1alpha1.ProxyReplicaPhaseStopped, ctrlv1alpha1.ProxyReplicaPhaseFailed:
				log.Error(nil, "Proxy process is running but status is stopped or failed", "phase", status.Phase)
			}
		} else {
			status.Phase = ctrlv1alpha1.ProxyReplicaPhaseStopped
			status.Reason = fmt.Sprintf("Proxy replica exited: %v", ps.ProcState)
		}

		if err := r.Status().Update(ctx, p); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update Proxy: %w", err)
		}

		return ctrl.Result{}, nil // Deleted.
	}

	var requeueAfter time.Duration
	if ps.StartedAt.IsZero() {
		// TODO(dsky): Support Starlark config render here.
		if err := r.Start(ctx, envoy.WithBootstrapConfigYAML(p.Spec.Config)); err != nil {
			if fatalErr, ok := err.(envoy.FatalError); ok {
				status.Phase = ctrlv1alpha1.ProxyReplicaPhaseFailed
				status.Reason = fmt.Sprintf("failed to create proxy replica: %v", fatalErr)
				if err := r.Status().Update(ctx, p); err != nil {
					return reconcile.Result{}, fmt.Errorf("failed to update proxy status: %w", err)
				}

				return reconcile.Result{}, nil // Leave the proxy in failed state.
			}

			return reconcile.Result{}, fmt.Errorf("failed to create proxy: %w", err)
		}

		log.Info("Started Envoy")

		status.Phase = ctrlv1alpha1.ProxyReplicaPhasePending
		status.Reason = "Proxy replica is being created"
		if err := r.Status().Update(ctx, p); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update proxy replica status: %w", err)
		}

		return reconcile.Result{RequeueAfter: 2 * time.Second}, nil
	} else {
		if ps.Running {
			// TODO(dsky): Also needs a detach loop.
			log.Info("Proxy is running", "start_time", ps.StartedAt)
			//for _, addr := range p.Status.IPs {
			//	if err := r.attachAddr(ctx, addr); err != nil {
			//		return reconcile.Result{}, fmt.Errorf("failed to set address: %w", err)
			//	}
			//}
			status.Phase = ctrlv1alpha1.ProxyReplicaPhaseRunning
			status.Reason = "Running"
		} else {
			switch status.Phase {
			case ctrlv1alpha1.ProxyReplicaPhasePending:
				if time.Now().After(status.CreatedAt.Time.Add(proxyReplicaPendingTimeout)) {
					log.Error(nil, "Proxy replica failed to start in time", "timeout", proxyReplicaPendingTimeout, "start_time", ps.StartedAt)
					status.Phase = ctrlv1alpha1.ProxyReplicaPhaseFailed
					status.Reason = "Proxy replica failed to start"
				} else {
					status.Phase = ctrlv1alpha1.ProxyReplicaPhasePending
					status.Reason = "Proxy replica is being created"
				}
				requeueAfter = 2 * time.Second
			case ctrlv1alpha1.ProxyReplicaPhaseRunning:
				status.Phase = ctrlv1alpha1.ProxyReplicaPhaseFailed
				status.Reason = fmt.Sprintf("Proxy replica exited: %v", ps.ProcState)
			case ctrlv1alpha1.ProxyReplicaPhaseTerminating:
				status.Phase = ctrlv1alpha1.ProxyReplicaPhaseStopped
				status.Reason = "Proxy replica stopped"
			case ctrlv1alpha1.ProxyReplicaPhaseFailed, ctrlv1alpha1.ProxyReplicaPhaseStopped: // Do nothing.
			default:
				return reconcile.Result{}, fmt.Errorf("unknown proxy replica phase: %v", status.Phase)
			}
		}

		if err := r.Status().Update(ctx, p); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update proxy replica status: %w", err)
		}
	}

	return reconcile.Result{RequeueAfter: requeueAfter}, nil
}

func uidPredicate(uid string) predicate.Funcs {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		if obj == nil {
			return false
		}

		p, ok := obj.(*ctrlv1alpha1.Proxy)
		if !ok {
			return false
		}

		return uid == string(p.GetUID())
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
				uidPredicate(r.proxyUID),
			),
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
			RecoverPanic:            pointer.Bool(true),
		}).
		Complete(r)
}

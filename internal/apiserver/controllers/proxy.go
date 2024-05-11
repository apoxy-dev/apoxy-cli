// Package controllers implements Apoxy Control Plane-side controllers.
package controllers

import (
	"context"
	"fmt"
	"time"

	bootstrapv3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ctrlv1alpha1 "github.com/apoxy-dev/apoxy/api/controllers/v1alpha1"
)

const (
	terminationTimeout = 15 * time.Minute
)

type retryableError struct {
	error
}

var _ reconcile.Reconciler = &ProxyReconciler{}

// ProxyReconciler reconciles a Proxy object.
type ProxyReconciler struct {
	client.Client
	projectID string
}

// NewProxyReconciler returns a new reconcile.Reconciler.
func NewProxyReconciler(
	c client.Client,
	projectID string,
) *ProxyReconciler {
	return &ProxyReconciler{
		Client:    c,
		projectID: projectID,
	}
}

// Reconcile implements reconcile.Reconciler.
func (r *ProxyReconciler) Reconcile(ctx context.Context, request reconcile.Request) (ctrl.Result, error) {
	p := &ctrlv1alpha1.Proxy{}
	err := r.Get(ctx, request.NamespacedName, p)
	if errors.IsNotFound(err) {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get Proxy: %w", err)
	}

	log := log.FromContext(ctx, "name", p.Name)
	log.Info("Reconciling Proxy")

	if p.ObjectMeta.DeletionTimestamp.IsZero() { // Not being deleted, so ensure finalizer is present.
		if !controllerutil.ContainsFinalizer(p, ctrlv1alpha1.ProxyFinalizer) {
			log.Info("Adding finalizer to Proxy")
			controllerutil.AddFinalizer(p, ctrlv1alpha1.ProxyFinalizer)
			if err := r.Update(ctx, p); err != nil {
				return ctrl.Result{}, err
			}
		}
	} else { // The object is being deleted
		log.Info("Proxy is being deleted", "phase", p.Status.Phase)

		switch p.Status.Phase {
		case ctrlv1alpha1.ProxyPhaseRunning, ctrlv1alpha1.ProxyPhasePending:
			synced, err := r.syncProxy(ctx, p, true)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to reconcile: %w", err)
			}
			if synced {
				log.Info("Backplane deleted")
				p.Status.Phase = ctrlv1alpha1.ProxyPhaseStopped
				p.Status.Reason = "Proxy deleted"
			} else {
				p.Status.Phase = ctrlv1alpha1.ProxyPhaseTerminating
			}

			if err := r.Status().Update(ctx, p); err != nil {
				return ctrl.Result{}, err
			}

			return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
		case ctrlv1alpha1.ProxyPhaseTerminating:
			synced, err := r.syncProxy(ctx, p, true)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to reconcile: %w", err)
			}
			if synced {
				log.Info("Backplane deleted")
				p.Status.Phase = ctrlv1alpha1.ProxyPhaseStopped
				p.Status.Reason = "Proxy deleted"
				if err := r.Status().Update(ctx, p); err != nil {
					return ctrl.Result{}, err
				}
			} else if time.Now().After(p.ObjectMeta.DeletionTimestamp.Add(terminationTimeout)) {
				log.Info("Proxy termination timed out. Setting status to stopped and cleaning up")
				p.Status.Phase = ctrlv1alpha1.ProxyPhaseStopped
				p.Status.Reason = fmt.Sprintf("Proxy termination timed out after %s", terminationTimeout)
				if err := r.Status().Update(ctx, p); err != nil {
					return ctrl.Result{}, err
				}
			} else {
				return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
			}
		case ctrlv1alpha1.ProxyPhaseStopped, ctrlv1alpha1.ProxyPhaseFailed:
			log.Info("Proxy is stopped or failed. Cleaning up")
		default:
			log.Error(nil, "Unknown phase", "app", string(p.UID), "phase", p.Status.Phase)
			return ctrl.Result{}, fmt.Errorf("unknown phase %s", p.Status.Phase)
		}

		switch p.Spec.Provider {
		case ctrlv1alpha1.InfraProviderCloud:
			p.Status.Phase = ctrlv1alpha1.ProxyPhaseFailed
			p.Status.Reason = "Infra provider not implemented"
			if err := r.Status().Update(ctx, p); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		case ctrlv1alpha1.InfraProviderUnmanaged:
			log.Info("Deleting unmanaged Proxy")
		default:
			return ctrl.Result{}, fmt.Errorf("unknown provider: %s", p.Spec.Provider)
		}

		controllerutil.RemoveFinalizer(p, ctrlv1alpha1.ProxyFinalizer)
		if err := r.Update(ctx, p); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil // Deleted.
	}

	switch p.Spec.Provider {
	case ctrlv1alpha1.InfraProviderCloud:
		switch p.Status.Phase {
		case ctrlv1alpha1.ProxyPhasePending:
			synced, err := r.syncProxy(ctx, p, false)
			if err != nil {
				log.Error(err, "Failed to assign Fly machine")
				if _, ok := err.(retryableError); ok {
					p.Status.Phase = ctrlv1alpha1.ProxyPhaseFailed
					p.Status.Reason = fmt.Sprintf("Failed to provision cloud proxy: %v", err)
					if err := r.Status().Update(ctx, p); err != nil {
						return ctrl.Result{}, fmt.Errorf("failed to update Proxy: %w", err)
					}
					return ctrl.Result{}, nil // Leave the Proxy in the failed state.
				}
				return ctrl.Result{}, fmt.Errorf("failed to reconcile Fly machines: %w", err)
			}

			if err = r.syncAddrs(ctx, p.Status); err != nil {
				p.Status.Phase = ctrlv1alpha1.ProxyPhaseFailed
				p.Status.Reason = fmt.Sprintf("Failed to reconcile addresses: %v", err)
			} else if synced {
				p.Status.Phase = ctrlv1alpha1.ProxyPhaseRunning
				p.Status.Reason = "Proxy is running"
			}

			if err := r.Status().Update(ctx, p); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to update Proxy: %w", err)
			} else {
				return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
			}
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Controller Manager.
func (r *ProxyReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ctrlv1alpha1.Proxy{}).
		Complete(r)
}

func (r *ProxyReconciler) syncProxy(ctx context.Context, p *ctrlv1alpha1.Proxy, delete bool) (bool, error) {
}

func (r *ProxyReconciler) syncAddrs(ctx context.Context, status *ctrlv1alpha1.ProxyStatus) error {
}

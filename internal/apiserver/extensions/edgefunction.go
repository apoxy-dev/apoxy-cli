// Package extensions implements extensions controllers.
package extensions

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	extensionsv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/extensions/v1alpha1"
)

var _ reconcile.Reconciler = &EdgeFunctionReconciler{}

// EdgeFunctionReconciler reconciles a Proxy object.
type EdgeFunctionReconciler struct {
	client.Client
}

// NewEdgeFuncReconciler returns a new reconcile.Reconciler.
func NewEdgeFuncReconciler(
	c client.Client,
) *EdgeFunctionReconciler {
	return &EdgeFunctionReconciler{
		Client: c,
	}
}

// Reconcile implements reconcile.Reconciler.
func (r *EdgeFunctionReconciler) Reconcile(ctx context.Context, request reconcile.Request) (ctrl.Result, error) {
	f := &extensionsv1alpha1.EdgeFunction{}
	err := r.Get(ctx, request.NamespacedName, f)
	if errors.IsNotFound(err) {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get EdgeFunction: %w", err)
	}

	log := log.FromContext(ctx, "name", f.Name)
	log.Info("Reconciling EdgeFunction", "phase", f.Status.Phase)

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Controller Manager.
func (r *EdgeFunctionReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&extensionsv1alpha1.EdgeFunction{}).
		Complete(r)
}

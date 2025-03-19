package controllers

import (
	"context"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
)

const (
	expiryDuration = 5 * time.Minute
)

// TunnelNodeReconciler implements a basic garbage collector for dead/orphaned
// TunnelNode objects.
type TunnelNodeReconciler struct {
	client.Client
}

func NewTunnelNodeReconciler(
	c client.Client,
) *TunnelNodeReconciler {
	return &TunnelNodeReconciler{
		Client: c,
	}
}

func (r *TunnelNodeReconciler) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx, "name", req.Name)

	log.Info("Reconciling TunnelNode")

	return ctrl.Result{}, nil
}

func (r *TunnelNodeReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha.TunnelNode{}).
		Complete(r)
}

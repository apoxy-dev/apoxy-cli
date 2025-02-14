package controllers

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	startTime time.Time
}

func NewTunnelNodeReconciler(
	c client.Client,
) *TunnelNodeReconciler {
	return &TunnelNodeReconciler{
		Client:    c,
		startTime: time.Now(),
	}
}

func (r *TunnelNodeReconciler) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx, "name", req.Name)

	// Skip the deletion process if the controller has been running for less than
	// a minute. Gives time for the TunnelNode processes to check in to the API
	// server.
	now := time.Now()
	if now.Sub(r.startTime) < time.Minute {
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	var tn corev1alpha.TunnelNode
	if err := r.Get(ctx, req.NamespacedName, &tn); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Check if the last synced time is more than 5 minutes ago.
	// If so, assume the node is dead and delete it.
	expiryTime := metav1.NewTime(now.Add(-expiryDuration))
	// Delete the tunnel node if it's been more than expiryDuration since the last
	// sync or since it was created if no sync was ever recorded.
	if (tn.Status.LastSynced == nil && tn.CreationTimestamp.Time.Before(expiryTime.Time)) ||
		(tn.Status.LastSynced != nil && tn.Status.LastSynced.Time.Before(expiryTime.Time)) {
		log.Info("Deleting dead TunnelNode", "lastSynced", tn.Status.LastSynced)

		if err := r.Delete(ctx, &tn); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Check again in a minute.
	return ctrl.Result{RequeueAfter: time.Minute}, nil
}

func (r *TunnelNodeReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha.TunnelNode{}).
		Complete(r)
}

// SetStartTime sets the start time of the reconciler. Used for testing.
func (r *TunnelNodeReconciler) SetStartTime(t time.Time) {
	r.startTime = t
}

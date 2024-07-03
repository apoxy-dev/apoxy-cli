package controllers

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ctrlv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/controllers/v1alpha1"
	"github.com/apoxy-dev/apoxy-cli/api/extensions/v1alpha1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
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
	f := &v1alpha1.EdgeFunction{}
	err := r.Get(ctx, request.NamespacedName, f)
	if errors.IsNotFound(err) {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get EdgeFunction: %w", err)
	}

	log := clog.FromContext(ctx, "name", f.Name)
	log.Info("Reconciling EdgeFunction", "phase", f.Status.Phase)

	return ctrl.Result{}, nil
}

func targetRefPredicate(proxyName string) predicate.Funcs {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		if obj == nil {
			return false
		}

		f, ok := obj.(*v1alpha1.EdgeFunction)
		if !ok {
			return false
		}

		for _, ref := range f.Spec.TargetRefs {
			if ref.Group == ctrlv1alpha1.GroupName &&
				ref.Kind == "Proxy" &&
				ref.Name == gwapiv1.ObjectName(proxyName) {
				return true
			}
		}

		return false
	})
}

func statusReadyPredicate() predicate.Funcs {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		if obj == nil {
			return false
		}

		f, ok := obj.(*v1alpha1.EdgeFunction)
		if !ok {
			return false
		}

		return f.Status.Phase == v1alpha1.EdgeFunctionPhaseReady
	})
}

// SetupWithManager sets up the controller with the Controller Manager.
func (r *EdgeFunctionReconciler) SetupWithManager(
	ctx context.Context,
	mgr ctrl.Manager,
	proxyName string,
) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.EdgeFunction{},
			builder.WithPredicates(
				&predicate.ResourceVersionChangedPredicate{},
				targetRefPredicate(proxyName),
				statusReadyPredicate(),
			),
		).
		Complete(r)
}

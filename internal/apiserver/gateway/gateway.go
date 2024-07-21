// Package gateway implements Gateway API controllers.
package gateway

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/apoxy-dev/apoxy-cli/internal/gateway/gatewayapi"
	gatewayapirunner "github.com/apoxy-dev/apoxy-cli/internal/gateway/gatewayapi/runner"
	"github.com/apoxy-dev/apoxy-cli/internal/gateway/message"

	gatewayv1 "github.com/apoxy-dev/apoxy-cli/api/gateway/v1"
)

const (
	classGatewayIndex     = "classGatewayIndex"
	gatewayHTTPRouteIndex = "gatewayHTTPRouteIndex"
)

var _ reconcile.Reconciler = &GatewayReconciler{}

// GatewayReconciler reconciles a Proxy object.
type GatewayReconciler struct {
	client.Client

	resources *message.ProviderResources
}

// NewGatewayReconciler returns a new reconciler for Gateway API resources.
func NewGatewayReconciler(
	c client.Client,
	pr *message.ProviderResources,
) *GatewayReconciler {
	return &GatewayReconciler{
		Client:    c,
		resources: pr,
	}
}

// Reconcile implements reconcile.Reconciler.
func (r *GatewayReconciler) Reconcile(ctx context.Context, request reconcile.Request) (ctrl.Result, error) {
	log := clog.FromContext(ctx, "controller", request.Name)
	log.Info("Reconciling the GatewayClass")

	var gwcsl gatewayv1.GatewayClassList
	if err := r.List(ctx, &gwcsl); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list GatewayClasses: %w", err)
	}
	var gwcs []*gatewayv1.GatewayClass
	for _, gwc := range gwcsl.Items {
		if !gwc.DeletionTimestamp.IsZero() {
			log.V(1).Info("GatewayClass is being deleted", "name", gwc.Name)
			continue
		}
		if gwc.Spec.ControllerName == gatewayapirunner.ControllerName {
			log.Info("Reconciling GatewayClass", "name", gwc.Name)
			gwcs = append(gwcs, &gwc) // No longer requires copy since 1.22. See: https://go.dev/blog/loopvar-preview
		}
	}

	if len(gwcs) == 0 {
		log.Info("No matching GatewayClass objects found for controller")
		return ctrl.Result{}, nil
	}

	ress := make(gatewayapi.ControllerResources, 0, len(gwcs))
	for _, gwc := range gwcs {
		res := gatewayapi.NewResources()
		res.GatewayClass = &gwapiv1.GatewayClass{
			TypeMeta:   gwc.TypeMeta,
			ObjectMeta: gwc.ObjectMeta,
			Spec:       gwc.Spec,
			Status:     gwc.Status,
		}
		if err := r.reconcileGatewayClass(clog.IntoContext(ctx, log), gwc, res); err != nil {
			log.Error(err, "Failed to reconcile GatewayClass", "name", gwc.Name)
			continue
		}
		ress = append(ress, res)
	}

	r.resources.GatewayAPIResources.Store(gatewayapirunner.ControllerName, &ress)

	return ctrl.Result{}, nil
}

func (r *GatewayReconciler) reconcileGatewayClass(
	ctx context.Context,
	gwc *gatewayv1.GatewayClass,
	res *gatewayapi.Resources,
) error {
	log := clog.FromContext(ctx, "GatewayClass", gwc.Name)

	var gwsl gatewayv1.GatewayList
	if err := r.List(ctx, &gwsl, client.MatchingFields{classGatewayIndex: string(gwc.Name)}); err != nil {
		return fmt.Errorf("failed to list Gateways: %w", err)
	}
	var gws []*gatewayv1.Gateway
	for _, gw := range gwsl.Items {
		if !gw.DeletionTimestamp.IsZero() {
			log.V(1).Info("Gateway is being deleted", "name", gw.Name)
			continue
		}
		log.Info("Reconciling Gateway", "name", gw.Name)
		gws = append(gws, &gw) // No longer requires copy since 1.22. See: https://go.dev/blog/loopvar-preview
	}

	if len(gws) == 0 {
		log.Info("No matching Gateway objects found for GatewayClass")
		return nil
	}

	for _, gw := range gws {
		if err := r.reconcileGateway(clog.IntoContext(ctx, log), gw, res); err != nil {
			log.Error(err, "Failed to reconcile Gateway", "name", gw.Name)
			continue
		}
		res.Gateways = append(res.Gateways, &gwapiv1.Gateway{
			TypeMeta:   gw.TypeMeta,
			ObjectMeta: gw.ObjectMeta,
			Spec:       gw.Spec,
			Status:     gw.Status,
		})
	}

	return nil
}

func (r *GatewayReconciler) reconcileGateway(
	ctx context.Context,
	gw *gatewayv1.Gateway,
	res *gatewayapi.Resources,
) error {
	log := clog.FromContext(ctx, "Gateway", gw.Name)

	var hrsl gatewayv1.HTTPRouteList
	if err := r.List(ctx, &hrsl, client.MatchingFields{gatewayHTTPRouteIndex: string(gw.Name)}); err != nil {
		return fmt.Errorf("failed to list HTTPRoutes: %w", err)
	}

	var hrs []*gatewayv1.HTTPRoute
	for _, hr := range hrsl.Items {
		if !hr.DeletionTimestamp.IsZero() {
			log.V(1).Info("HTTPRoute is being deleted", "name", hr.Name)
			continue
		}
		log.Info("Reconciling HTTPRoute", "name", hr.Name)

		hrs = append(hrs, &hr) // No longer requires copy since 1.22. See: https://go.dev/blog/loopvar-preview
	}

	for _, hr := range hrs {
		res.HTTPRoutes = append(res.HTTPRoutes, &gwapiv1.HTTPRoute{
			TypeMeta:   hr.TypeMeta,
			ObjectMeta: hr.ObjectMeta,
			Spec:       hr.Spec,
			Status:     hr.Status,
		})
	}

	return nil
}

// SetupWithManager sets up the controller with the Controller Manager.
func (r *GatewayReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(ctx, &gatewayv1.Gateway{}, classGatewayIndex, func(obj client.Object) []string {
		return []string{string(obj.(*gatewayv1.Gateway).Spec.GatewayClassName)}
	}); err != nil {
		return fmt.Errorf("failed to setup field indexer: %w", err)
	}
	if err := mgr.GetFieldIndexer().IndexField(ctx, &gatewayv1.HTTPRoute{}, gatewayHTTPRouteIndex, func(obj client.Object) []string {
		route := obj.(*gatewayv1.HTTPRoute)
		var gateways []string
		for _, ref := range route.Spec.ParentRefs {
			if ref.Kind == nil || *ref.Kind == "Gateway" {
				gateways = append(gateways, string(ref.Name))
			}
		}
		return gateways
	}); err != nil {
		return fmt.Errorf("failed to setup field indexer: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.GatewayClass{}).
		Watches(
			&gatewayv1.GatewayClass{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueClass),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Watches(
			&gatewayv1.Gateway{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueClass),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Watches(
			&gatewayv1.HTTPRoute{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueClass),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Complete(r)
}

func (r *GatewayReconciler) enqueueClass(_ context.Context, _ client.Object) []reconcile.Request {
	return []reconcile.Request{{NamespacedName: types.NamespacedName{
		Name: gatewayapirunner.ControllerName,
	}}}
}

// Package gateway implements Gateway API controllers.
package gateway

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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

	ctrlv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/controllers/v1alpha1"
	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	extensionsv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/extensions/v1alpha1"
	gatewayv1 "github.com/apoxy-dev/apoxy-cli/api/gateway/v1"
)

const (
	classGatewayIndex      = "classGatewayIndex"
	gatewayHTTPRouteIndex  = "gatewayHTTPRouteIndex"
	backendHTTPRouteIndex  = "backendHTTPRouteIndex"
	gatewayInfraRefIndex   = "gatewayInfraRefIndex"
	edgeFunctionReadyIndex = "edgeFunctionReadyIndex"
)

var (
	conv = runtime.DefaultUnstructuredConverter

	_ reconcile.Reconciler = &GatewayReconciler{}
)

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

	res := gatewayapi.NewResources()
	extRefs, err := r.getExtensionRefs(ctx)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get extension references: %w", err)
	}

	ress := make(gatewayapi.ControllerResources, 0, len(gwcs))
	for _, gwc := range gwcs {
		res.GatewayClass = &gwapiv1.GatewayClass{
			TypeMeta:   gwc.TypeMeta,
			ObjectMeta: gwc.ObjectMeta,
			Spec:       gwc.Spec,
			Status:     gwc.Status,
		}

		if err := r.reconcileGateways(clog.IntoContext(ctx, log), gwc, extRefs, res); err != nil {
			log.Error(err, "Failed to reconcile GatewayClass", "name", gwc.Name)
		}
		if err := r.reconcileBackends(clog.IntoContext(ctx, log), res); err != nil {
			log.Error(err, "Failed to reconcile BackendRefs for GatewayClass", "name", gwc.Name)
		}

		ress = append(ress, res)
	}

	r.resources.GatewayAPIResources.Store(gatewayapirunner.ControllerName, &ress)

	return ctrl.Result{}, nil
}

type extensionRefKey struct {
	Name      string
	GroupKind schema.GroupKind
}

func (r *GatewayReconciler) getExtensionRefs(
	ctx context.Context,
) (map[extensionRefKey]*unstructured.Unstructured, error) {
	extRefs := make(map[extensionRefKey]*unstructured.Unstructured)

	funls := extensionsv1alpha1.EdgeFunctionList{}
	if err := r.List(ctx, &funls, client.MatchingFields{edgeFunctionReadyIndex: "true"}); err != nil {
		return nil, fmt.Errorf("failed to list EdgeFunctions: %w", err)
	}
	for _, fun := range funls.Items {
		un, err := conv.ToUnstructured(&fun)
		if err != nil {
			return nil, fmt.Errorf("failed to convert EdgeFunction to Unstructured: %w", err)
		}

		extRefs[extensionRefKey{
			Name:      fun.Name,
			GroupKind: schema.GroupKind{Group: fun.GroupVersionKind().Group, Kind: "EdgeFunction"},
		}] = &unstructured.Unstructured{Object: un}
	}

	// TODO(dilyevsky): Process other extensions.

	return extRefs, nil
}

func (r *GatewayReconciler) reconcileGateways(
	ctx context.Context,
	gwc *gatewayv1.GatewayClass,
	extRefs map[extensionRefKey]*unstructured.Unstructured,
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
		if gw.Spec.Infrastructure == nil || gw.Spec.Infrastructure.ParametersRef.Kind != "Proxy" {
			log.Info("Gateway does not have a Proxy reference", "name", gw.Name)
			continue
		}

		// Check if the Proxy object actually exists.
		var proxy ctrlv1alpha1.Proxy
		pn := types.NamespacedName{Name: gw.Spec.Infrastructure.ParametersRef.Name}
		if err := r.Get(ctx, pn, &proxy); err != nil {
			return fmt.Errorf("failed to get Proxy %s: %w", pn, err)
		}
		// Add the Proxy object to the resources if it doesn't already exist.
		if _, ok := res.GetProxy(proxy.Name); !ok {
			res.Proxies = append(res.Proxies, &proxy)
		}

		if err := r.reconcileHTTPRoutes(clog.IntoContext(ctx, log), gw, extRefs, res); err != nil {
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

func (r *GatewayReconciler) reconcileHTTPRoutes(
	ctx context.Context,
	gw *gatewayv1.Gateway,
	extRefs map[extensionRefKey]*unstructured.Unstructured,
	res *gatewayapi.Resources,
) error {
	log := clog.FromContext(ctx, "Gateway", gw.Name)

	var hrsl gatewayv1.HTTPRouteList
	if err := r.List(ctx, &hrsl, client.MatchingFields{gatewayHTTPRouteIndex: string(gw.Name)}); err != nil {
		return fmt.Errorf("failed to list HTTPRoutes: %w", err)
	}

	for _, hr := range hrsl.Items {
		if !hr.DeletionTimestamp.IsZero() {
			log.V(1).Info("HTTPRoute is being deleted", "name", hr.Name)
			continue
		}

		log.Info("Reconciling HTTPRoute", "name", hr.Name)

		for _, rule := range hr.Spec.Rules {
			for _, filter := range rule.Filters {
				if filter.ExtensionRef != nil {
					key := extensionRefKey{
						Name: string(filter.ExtensionRef.Name),
						GroupKind: schema.GroupKind{
							Group: string(filter.ExtensionRef.Group),
							Kind:  string(filter.ExtensionRef.Kind),
						},
					}
					if ref, ok := extRefs[key]; ok {
						log.Info("Found extension reference",
							"name", ref.GetName(), "gvk", ref.GroupVersionKind())
						res.ExtensionRefFilters = append(res.ExtensionRefFilters, *ref)
					}
				}
			}
		}

		res.HTTPRoutes = append(res.HTTPRoutes, &gwapiv1.HTTPRoute{
			TypeMeta:   hr.TypeMeta,
			ObjectMeta: hr.ObjectMeta,
			Spec:       hr.Spec,
			Status:     hr.Status,
		})
	}

	return nil
}

func (r *GatewayReconciler) reconcileBackends(
	ctx context.Context,
	res *gatewayapi.Resources,
) error {
	log := clog.FromContext(ctx)

	var bl corev1alpha.BackendList
	if err := r.List(ctx, &bl); err != nil {
		return fmt.Errorf("failed to list Backends: %w", err)
	}

	for _, b := range bl.Items {
		if !b.DeletionTimestamp.IsZero() {
			log.V(1).Info("Backend is being deleted", "name", b.Name)
			continue
		}

		var hrsl gatewayv1.HTTPRouteList
		if err := r.List(ctx, &hrsl, client.MatchingFields{backendHTTPRouteIndex: string(b.Name)}); err != nil {
			return fmt.Errorf("failed to list HTTPRoutes for Backend %s: %w", b.Name, err)
		} else if len(hrsl.Items) == 0 {
			log.Info("No matching HTTPRoute objects found for Backend", "name", b.Name)
			continue
		}

		log.Info("Reconciling Backend", "name", b.Name)

		res.Backends = append(res.Backends, &b) // No longer requires copy since 1.22. See: https://go.dev/blog/loopvar-preview
	}

	return nil
}

// SetupWithManager sets up the controller with the Controller Manager.
func (r *GatewayReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	// Indexes Gateway objects by the name of the referenced GatewayClass object.
	if err := mgr.GetFieldIndexer().IndexField(ctx, &gatewayv1.Gateway{}, classGatewayIndex, func(obj client.Object) []string {
		return []string{string(obj.(*gatewayv1.Gateway).Spec.GatewayClassName)}
	}); err != nil {
		return fmt.Errorf("failed to setup field indexer: %w", err)
	}
	// Indexes Gateway objects by the name of the referenced Proxy object.
	if err := mgr.GetFieldIndexer().IndexField(ctx, &gatewayv1.Gateway{}, gatewayInfraRefIndex, func(obj client.Object) []string {
		var ref *gwapiv1.LocalParametersReference
		if obj.(*gatewayv1.Gateway).Spec.Infrastructure != nil {
			ref = obj.(*gatewayv1.Gateway).Spec.Infrastructure.ParametersRef
		}
		if ref != nil && ref.Kind == "Proxy" && ref.Name != "" {
			return []string{string(ref.Name)}
		}

		return nil
	}); err != nil {
		return fmt.Errorf("failed to setup field indexer: %w", err)
	}
	// Indexes HTTPRoute objects by the name of the referenced Gateway object.
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
	// Indexes HTTPRoute objects by the name of the referenced Backend object.
	if err := mgr.GetFieldIndexer().IndexField(ctx, &gatewayv1.HTTPRoute{}, backendHTTPRouteIndex, func(obj client.Object) []string {
		route := obj.(*gatewayv1.HTTPRoute)
		var backends []string
		for _, ref := range route.Spec.Rules {
			for _, backend := range ref.BackendRefs {
				if backend.Kind != nil && *backend.Kind == "Backend" {
					backends = append(backends, string(backend.Name))
				}
			}
		}
		return backends
	}); err != nil {
		return fmt.Errorf("failed to setup field indexer: %w", err)
	}
	// Index EdgeFunction objects that are in the "Ready" phase.
	if err := mgr.GetFieldIndexer().IndexField(ctx, &extensionsv1alpha1.EdgeFunction{}, edgeFunctionReadyIndex, func(obj client.Object) []string {
		if obj.(*extensionsv1alpha1.EdgeFunction).Status.Phase == extensionsv1alpha1.EdgeFunctionPhaseReady {
			return []string{"true"}
		}
		return nil
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
		Watches(
			&corev1alpha.Backend{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueClass),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Watches(
			&extensionsv1alpha1.EdgeFunction{},
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

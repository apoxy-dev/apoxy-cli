package v1alpha1

import (
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

func (r *EdgeFunction) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

var _ webhook.Defaulter = &EdgeFunction{}

// Default sets the default values for an EdgeFunction.
func (r *EdgeFunction) Default() {
	if r.Status.Phase == "" {
		r.Status.Phase = EdgeFunctionPhasePreparing
	}
}

package v1alpha1

import (
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

func (r *Proxy) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

var _ webhook.Defaulter = &Proxy{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *Proxy) Default() {
	r.Status.Phase = ProxyPhasePending
}

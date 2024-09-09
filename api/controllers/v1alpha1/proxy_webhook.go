package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

func (r *Proxy) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

var _ webhook.Defaulter = &Proxy{}

// Default sets the default values for a Proxy.
func (r *Proxy) Default() {
	if r.Status.Phase == "" {
		r.Status.Phase = ProxyPhasePending
	}
	if r.Spec.DrainTimeout == nil {
		r.Spec.DrainTimeout = &metav1.Duration{Duration: DefaultDrainTimeout}
	}
}

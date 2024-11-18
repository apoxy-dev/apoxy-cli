package v1alpha

import (
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

func (r *Domain) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

var _ webhook.Defaulter = &Domain{}

// Default sets the default values for a Domain.
func (r *Domain) Default() {
	if r.Status.Phase == "" {
		r.Status.Phase = DomainPhasePending
	}
	if r.Spec.Target.DNS != nil && r.Spec.Target.DNS.TTL == nil {
		defaultTTL := int32(20)
		r.Spec.Target.DNS.TTL = &defaultTTL
	}
}

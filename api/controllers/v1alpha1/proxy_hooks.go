package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy"
)

var _ resourcestrategy.Defaulter = &Proxy{}

// Default sets the default values for a Proxy.
func (r *Proxy) Default() {
	if r.Status.Phase == "" {
		r.Status.Phase = ProxyPhasePending
	}
	if r.Spec.DrainTimeout == nil {
		r.Spec.DrainTimeout = &metav1.Duration{Duration: DefaultDrainTimeout}
	}
}

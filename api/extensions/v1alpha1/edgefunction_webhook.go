package v1alpha1

import (
	"encoding/base64"
	"errors"

	runtime "k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
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

	if r.Spec.Code.GoPluginSource != nil &&
		r.Spec.Code.GoPluginSource.OCI != nil &&
		r.Spec.Code.GoPluginSource.OCI.Credentials != nil &&
		r.Spec.Code.GoPluginSource.OCI.Credentials.Password != "" {
		var bs []byte
		base64.StdEncoding.Encode(bs, []byte(r.Spec.Code.GoPluginSource.OCI.Credentials.Password))
		r.Spec.Code.GoPluginSource.OCI.Credentials.PasswordData = bs
		r.Spec.Code.GoPluginSource.OCI.Credentials.Password = ""
	}
}

var _ webhook.Validator = &EdgeFunction{}

// validate validates the EdgeFunction and returns an error if it is invalid.
// +kubebuilder:docs-gen:collapse=validate
func (r *EdgeFunction) validate() error {
	if r.Spec.Code.GoPluginSource == nil && r.Spec.Code.JsSource == nil &&
		r.Spec.Code.WasmSource == nil {
		return errors.New("code.goPluginSource, code.jsSource, or code.wasmSource must be specified")
	}
	if r.Spec.Code.GoPluginSource != nil {
		if r.Spec.Code.GoPluginSource.OCI == nil && r.Spec.Code.GoPluginSource.URL == nil {
			return errors.New("code.goPluginSource.oci or code.goPluginSource.url must be specified")
		}
		if r.Spec.Code.GoPluginSource.OCI != nil && r.Spec.Code.GoPluginSource.URL != nil {
			return errors.New("code.goPluginSource.oci and code.goPluginSource.url cannot both be specified")
		}
		if r.Spec.Code.GoPluginSource.OCI != nil {
			if r.Spec.Code.GoPluginSource.OCI.Repo == "" {
				return errors.New("code.goPluginSource.oci.repo must be specified")
			}
			if r.Spec.Code.GoPluginSource.OCI.Credentials != nil && r.Spec.Code.GoPluginSource.OCI.CredentialsRef != nil {
				return errors.New("code.goPluginSource.oci.credentials and code.goPluginSource.oci.credentialsRef cannot both be specified")
			}
		}
	}
	return nil
}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *EdgeFunction) ValidateCreate() (admission.Warnings, error) {
	return nil, r.validate()
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *EdgeFunction) ValidateUpdate(old runtime.Object) (admission.Warnings, error) {
	return nil, r.validate()
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *EdgeFunction) ValidateDelete() (admission.Warnings, error) {
	return nil, nil
}

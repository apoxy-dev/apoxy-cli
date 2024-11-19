package v1alpha1

import (
	"context"
	"encoding/base64"
	"strings"

	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy"
)

var _ resourcestrategy.Defaulter = &EdgeFunction{}

// Default sets the default values for an EdgeFunction.
func (r *EdgeFunction) Default() {
	if r.Status.Phase == "" {
		r.Status.Phase = EdgeFunctionPhasePreparing
	}

	if r.Spec.Code.GoPluginSource != nil &&
		r.Spec.Code.GoPluginSource.OCI != nil &&
		r.Spec.Code.GoPluginSource.OCI.Credentials != nil &&
		r.Spec.Code.GoPluginSource.OCI.Credentials.Password != "" {
		enc := base64.StdEncoding.EncodeToString([]byte(r.Spec.Code.GoPluginSource.OCI.Credentials.Password))
		r.Spec.Code.GoPluginSource.OCI.Credentials.PasswordData = []byte(enc)
		r.Spec.Code.GoPluginSource.OCI.Credentials.Password = ""
	}
}

var _ resourcestrategy.Validater = &EdgeFunction{}
var _ resourcestrategy.ValidateUpdater = &EdgeFunction{}

// validate validates the EdgeFunction and returns an error if it is invalid.
func (r *EdgeFunction) validate() field.ErrorList {
	errs := field.ErrorList{}

	if r.Spec.Code.GoPluginSource == nil && r.Spec.Code.JsSource == nil &&
		r.Spec.Code.WasmSource == nil {
		errs = append(errs, field.Invalid(field.NewPath("spec").Child("code"), r, "code.goPluginSource, code.jsSource, or code.wasmSource must be specified"))
	}
	if r.Spec.Code.GoPluginSource != nil {
		if r.Spec.Code.JsSource != nil || r.Spec.Code.WasmSource != nil {
			errs = append(errs, field.Invalid(field.NewPath("spec").Child("code"), r, "code.jsSource and code.wasmSource cannot be specified when code.goPluginSource is specified"))
		}

		if r.Spec.Code.GoPluginSource.OCI == nil && r.Spec.Code.GoPluginSource.URL == nil {
			errs = append(errs, field.Invalid(field.NewPath("spec").Child("code").Child("goPluginSource"), r, "code.goPluginSource.oci or code.goPluginSource.url must be specified"))
		}
		if r.Spec.Code.GoPluginSource.OCI != nil && r.Spec.Code.GoPluginSource.URL != nil {
			errs = append(errs, field.Invalid(field.NewPath("spec").Child("code").Child("goPluginSource"), r, "code.goPluginSource.oci and code.goPluginSource.url cannot both be specified"))
		}
		if r.Spec.Code.GoPluginSource.OCI != nil {
			if r.Spec.Code.GoPluginSource.OCI.Repo == "" {
				errs = append(errs, field.Invalid(field.NewPath("spec").Child("code").Child("goPluginSource").Child("oci").Child("repo"), r, "code.goPluginSource.oci.repo must be specified"))
			}
			if r.Spec.Code.GoPluginSource.OCI.Credentials != nil && r.Spec.Code.GoPluginSource.OCI.CredentialsRef != nil {
				errs = append(errs, field.Invalid(field.NewPath("spec").Child("code").Child("goPluginSource").Child("oci"), r, "code.goPluginSource.oci.credentials and code.goPluginSource.oci.credentialsRef cannot both be specified"))
			}
		}
	} else if r.Spec.Code.JsSource != nil {
		if r.Spec.Code.GoPluginSource != nil || r.Spec.Code.WasmSource != nil {
			errs = append(errs, field.Invalid(field.NewPath("spec").Child("code"), r, "code.goPluginSource and code.wasmSource cannot be specified when code.jsSource is specified"))
		}

		if r.Spec.Code.JsSource.Assets == nil && r.Spec.Code.JsSource.Git == nil && r.Spec.Code.JsSource.Npm == nil {
			errs = append(errs, field.Invalid(field.NewPath("spec").Child("code").Child("jsSource"), r, "code.jsSource.assets or code.jsSource.url must be specified"))
		}

		if r.Spec.Code.JsSource.Assets != nil && r.Spec.Code.JsSource.Git != nil {
			errs = append(errs, field.Invalid(field.NewPath("spec").Child("code").Child("jsSource"), r, "code.jsSource.assets and code.jsSource.git cannot both be specified"))
		}
		if r.Spec.Code.JsSource.Assets != nil && r.Spec.Code.JsSource.Npm != nil {
			errs = append(errs, field.Invalid(field.NewPath("spec").Child("code").Child("jsSource"), r, "code.jsSource.assets and code.jsSource.npm cannot both be specified"))
		}
		if r.Spec.Code.JsSource.Git != nil && r.Spec.Code.JsSource.Npm != nil {
			errs = append(errs, field.Invalid(field.NewPath("spec").Child("code").Child("jsSource"), r, "code.jsSource.git and code.jsSource.npm cannot both be specified"))
		}

		if r.Spec.Code.JsSource.Assets != nil {
			for _, f := range r.Spec.Code.JsSource.Assets.Files {
				if f.Path == "" {
					errs = append(errs, field.Invalid(field.NewPath("spec").Child("code").Child("jsSource").Child("assets").Child("files").Child("path"), r, "code.jsSource.assets.files.path must be specified"))
				}
				if f.Content == "" {
					errs = append(errs, field.Invalid(field.NewPath("spec").Child("code").Child("jsSource").Child("assets").Child("files").Child("content"), r, "code.jsSource.assets.files.content must be specified"))
				}

				if f.Path == ".." || strings.HasPrefix(f.Path, "../") {
					errs = append(errs, field.Invalid(field.NewPath("spec").Child("code").Child("jsSource").Child("assets").Child("files").Child("path"), r, "code.jsSource.assets.files.path cannot start with '..'"))
				}
				if strings.Contains(f.Path, "\\") {
					errs = append(errs, field.Invalid(field.NewPath("spec").Child("code").Child("jsSource").Child("assets").Child("files").Child("path"), r, "code.jsSource.assets.files.path cannot contain backslashes"))
				}
			}
		}
	}

	return errs
}

func (r *EdgeFunction) Validate(ctx context.Context) field.ErrorList {
	return r.validate()
}

func (r *EdgeFunction) ValidateUpdate(ctx context.Context, obj runtime.Object) field.ErrorList {
	fun := obj.(*EdgeFunction)
	return fun.validate()
}

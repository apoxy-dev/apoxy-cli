package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"

	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type SourceFile struct {
	// Path is the path to the source file.
	Path string `json:"path"`

	// Content is the content of the source file.
	Content string `json:"content"`
}

type JavaScriptAssetsSource struct {
	Files []SourceFile `json:"files"`
}

type JavaScriptGitSource struct {
	// Repository is the git repository URL.
	Repository string `json:"repository"`

	// Branch is the git branch.
	// +optional
	Branch string `json:"branch,omitempty"`

	// Commit is the git commit.
	// +optional
	Commit string `json:"commit,omitempty"`
}

type JavaScriptNpmSource struct {
	// Package is the npm package name.
	Package string `json:"package"`

	// Version is the npm package version.
	// +optional
	Version string `json:"version,omitempty"`
}

// JavaScriptSource provides sources for the JavaScript function runtime.
// Only one of the fields may be specified.
type JavaScriptSource struct {
	// Entrypoint is the entrypoint path to the function.
	Entrypoint string `json:"entrypoint"`

	// Asset accepts a list of source files to be included in the function.
	// Only one of Assets, Git, or Npm may be specified.
	// +optional
	Assets *JavaScriptAssetsSource `json:"assets,omitempty"`

	// Git is the git source for the function.
	// Only one of Assets, Git, or Npm may be specified.
	// +optional
	Git *JavaScriptGitSource `json:"git,omitempty"`

	// Npm is the npm source for the function.
	// Only one of Assets, Git, or Npm may be specified.
	// +optional
	Npm *JavaScriptNpmSource `json:"npm,omitempty"`
}

type WasmSource struct {
	// URL is the URL to the WebAssembly binary.
	URL string `json:"url"`
}

type OCICredentialsObjectReference struct {
	// Group is the group of the target resource.
	// Currently only controllers.apoxy.dev/v1alpha1 is supported.
	Group gwapiv1.Group `json:"group"`

	// Kind is kind of the target resource.
	// Supports Secret with on-prem deploys and
	Kind gwapiv1.Kind `json:"kind"`

	// Name is the name of the target resource.
	Name gwapiv1.ObjectName `json:"name"`
}

type OCICredentials struct {
	// Username is the username for the OCI registry.
	Username string `json:"username,omitempty"`

	// Password is the password for the OCI registry. This field is write-only
	// and is not returned in the response.
	Password string `json:"password,omitempty"`

	// PasswordData is the base64 encoded password for the OCI registry.
	PasswordData []byte `json:"passwordData,omitempty"`
}

const (
	ImageConfigMediaType = "application/vnd.apoxy.dev.image.config.v1+json"
	ImageLayerMediaType  = "application/vnd.apoxy.dev.image.content.v1.tar+gzip"
)

type OCIImageRef struct {
	// Repo is the repository of the OCI image.
	Repo string `json:"repo"`

	// Tag is the tag of the OCI image.
	// +optional
	// +kubebuilder:default="latest"
	Tag string `json:"tag"`

	// Credentials is the credentials for pulling the OCI image.
	// Only one of Credentials or CredentialsRef may be specified.
	// +optional
	Credentials *OCICredentials `json:"credentials,omitempty"`

	// CredentialsRef is the reference to the secret containing the credentials for pulling the OCI image.
	// Only one of Credentials or CredentialsRef may be specified.
	// +optional
	CredentialsRef *OCICredentialsObjectReference `json:"credentialsRef,omitempty"`
}

type GoPluginSource struct {
	// URL is the URL to the Go plugin .so
	// +optional
	URL *string `json:"url"`

	// OCI is the OCI image reference to the Go plugin.
	// +optional
	OCI *OCIImageRef `json:"oci,omitempty"`

	// PluginConfig is the configuration passed to the Go plugin as JSON-encoded
	// structpb.Struct message. Plugin will receive it as anypb.Any message.
	// +optional
	PluginConfig string `json:"pluginConfig,omitempty"`
}

type EdgeFunctionCodeSource struct {
	// Metadata of the function source.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// JsSource specifies sources for the JavaScript function runtime.
	// If set/modified, a function will undergo a build step to compile the
	// JavaScript source into a WebAssembly binary before it is deployed.
	// +optional
	JsSource *JavaScriptSource `json:"jsSource,omitempty"`

	// WasmSource specifies sources for the WebAssembly function runtime.
	// +optional
	WasmSource *WasmSource `json:"wasmSource,omitempty"`

	// GoSource specifies sources for the Go filter plugin.
	// This option is only available for non-cloud (kubernets, unmanaged, etc)
	// Proxy providers.
	// +optional
	GoPluginSource *GoPluginSource `json:"goPluginSource,omitempty"`
}

type EnvVar struct {
	// Name of the environment variable.
	Name string `json:"name"`

	// Value of the environment variable.
	Value string `json:"value"`
}

type RuntimeCapabilities struct {
	// FetchAPI is the capability to fetch data from the internet.
	// Defaults to true.
	// +optional
	FetchAPI *bool `json:"fetchAPI,omitempty"`
}

type RuntimeConfig struct {
	// Timeout is the maximum time the function is allowed to run.
	// Defaults to 30 seconds but can be increased depending on your plan.
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`

	// Capabilities is the list of capabilities granted to the function.
	// +optional
	Capabilities *RuntimeCapabilities `json:"capabilities"`
}

type EdgeFunctionTargetReference struct {
	// Group is the group of the target resource.
	// Currently only controllers.apoxy.dev/v1alpha1 is supported.
	Group gwapiv1.Group `json:"group"`

	// Kind is kind of the target resource.
	// Currently only Proxy is supported.
	Kind gwapiv1.Kind `json:"kind"`

	// Name is the name of the target resource.
	Name gwapiv1.ObjectName `json:"name"`
}

type EdgeFunctionSpec struct {
	// TargetRefs are the resources that the function is associated with.
	// Currently we only support Proxy targets and not Routes or Backends.
	TargetRefs []EdgeFunctionTargetReference `json:"targetRefs"`

	// Code is the source of the function code/binary.
	Code EdgeFunctionCodeSource `json:"code"`

	// Env is a list of environment variables to set in the function
	// runtime.
	// These will be available via WASIp1 environ* routines as well as Apoxy Runtime SDK APIs.
	// +optional
	Env []EnvVar `json:"env,omitempty"`

	// RuntimeConfig is the configuration for the function runtime.
	// +optional
	RuntimeConfig RuntimeConfig `json:"runtimeConfig"`
}

type EdgeFunctionRevision struct {
	// Ref is the reference to the function revision.
	Ref string `json:"ref"`

	// Status is the status of the function revision.
	// +optional
	Status string `json:"status,omitempty"`

	// CreatedAt is the time the function revision was created.
	CreatedAt metav1.Time `json:"createdAt"`
}

type EdgeFunctionPhase string

const (
	// EdgeFunctionPhasePreparing means the function is being prepared.
	EdgeFunctionPhasePreparing EdgeFunctionPhase = "Preparing"
	// EdgeFunctionPhaseReady means the function is ready.
	EdgeFunctionPhaseReady EdgeFunctionPhase = "Ready"
	// EdgeFunctionPhaseUpdating means the function is being updated.
	EdgeFunctionPhaseUpdating EdgeFunctionPhase = "Updating"
	// EdgeFunctionPhaseFailed means the function has failed.
	EdgeFunctionPhaseFailed EdgeFunctionPhase = "Failed"
	// EdgeFunctionPhaseUnknown means the function is in an unknown state.
	EdgeFunctionPhaseUnknown EdgeFunctionPhase = "Unknown"
)

type EdgeFunctionStatus struct {
	// Phase is the current phase of the function.
	Phase EdgeFunctionPhase `json:"phase"`

	// Message is a human-readable message indicating details about the function.
	// +optional
	Message string `json:"message,omitempty"`

	// Revisions is a list of function revisions.
	// Latest revision is the first element in the list.
	// +optional
	Revisions []EdgeFunctionRevision `json:"revisions,omitempty"`
}

var _ resource.StatusSubResource = &EdgeFunctionStatus{}

func (ps *EdgeFunctionStatus) SubResourceName() string {
	return "status"
}

func (ps *EdgeFunctionStatus) CopyTo(parent resource.ObjectWithStatusSubResource) {
	parent.(*EdgeFunction).Status = *ps
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:subresource:log

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type EdgeFunction struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EdgeFunctionSpec   `json:"spec,omitempty"`
	Status EdgeFunctionStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &EdgeFunction{}
	_ resource.Object                      = &EdgeFunction{}
	_ resource.ObjectWithStatusSubResource = &EdgeFunction{}
	_ rest.SingularNameProvider            = &EdgeFunction{}
)

func (p *EdgeFunction) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *EdgeFunction) NamespaceScoped() bool {
	return false
}

func (p *EdgeFunction) New() runtime.Object {
	return &EdgeFunction{}
}

func (p *EdgeFunction) NewList() runtime.Object {
	return &EdgeFunctionList{}
}

func (p *EdgeFunction) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "edgefunctions",
	}
}

func (p *EdgeFunction) IsStorageVersion() bool {
	return true
}

func (p *EdgeFunction) GetSingularName() string {
	return "edgefunction"
}

func (p *EdgeFunction) GetStatus() resource.StatusSubResource {
	return &p.Status
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type EdgeFunctionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EdgeFunction `json:"items"`
}

var _ resource.ObjectList = &EdgeFunctionList{}

func (pl *EdgeFunctionList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

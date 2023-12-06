package v1alpha

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
)

const (
	ProxyFinalizer = "proxy.core.apoxy.dev/finalizer"
)

// FileAccessLog defines the file access log configuration.
type FileAccessLog struct {
	// Path where access logs collectors will look for access log files.
	// Accepts absolute paths, and paths relative to the Proxy's current working directory.
	// If empty, will use default path for the proxy type.
	// +optional
	Path string `json:"path,omitempty"`
}

// AccessLog defines the access log configuration.
type AccessLog struct {
	// FileAccessLog specifies the file access log configuration.
	FileAccessLog *FileAccessLog `json:"fileAccessLog,omitempty"`
}

// ProxyType defines the type of proxy.
type ProxyType string

const (
	// ProxyTypeEnvoy is the envoy proxy type.
	ProxyTypeEnvoy ProxyType = "envoy"
)

// InfraProvider defines the infrastructure provider where the proxy will be deployed.
type InfraProvider string

const (
	// InfraProviderCloud is the cloud provider.
	// This provider deploys proxies within Apoxy cloud.
	InfraProviderCloud InfraProvider = "cloud"
	// InfraProviderKubernetes is the kubernetes provider.
	// This provider is used to deploy the proxy as a kubernetes pod.
	InfraProviderKubernetes InfraProvider = "kubernetes"
)

// ProxySpec defines the desired specification of a Proxy.
type ProxySpec struct {
	// Proxy type (currently only envoy is supported).
	Type ProxyType `json:"type,omitempty"`

	// Provider is the infrastructure provider where the proxy will be deployed.
	// Defaults to "cloud" provider.
	Provider InfraProvider `json:"provider,omitempty"`

	// Node name of the proxy.
	// +optional
	NodeName string `json:"nodeName,omitempty"`

	// Proxy configuration.
	ConfigData string `json:"configData,omitempty"`

	// Reference to the IP (v4/v6) address attached to the proxy.
	// If not specified, the proxy will allocate default address
	// for the "cloud" provider. See other providers for their default
	// address allocation mechanism.
	// +optional
	AddressRef *corev1.ObjectReference `json:"addressRef,omitempty"`

	// Location (region) of the proxy instance.
	Location string `json:"location,omitempty"`

	// Access log collector configuration. This is used to configure the access log collector
	// that will be used to collect access logs from the proxy so proxy config should have the
	// configuration to produce access logs using the matching format/sink.
	AccessLog *AccessLog `json:"accessLog,omitempty"`

	// DynamicForwardProxy enables a dynamic forward proxy for sending
	// traffic to dynamically created upstreams based on the host
	// exctracted from the request.
	DynamicForwardProxy bool `json:"dynamicForwardProxy,omitempty"`
}

type ProxyPhase string

const (
	ProxyPhasePending     ProxyPhase = "Pending"
	ProxyPhaseRunning     ProxyPhase = "Running"
	ProxyPhaseTerminating ProxyPhase = "Terminating"
	ProxyPhaseStopped     ProxyPhase = "Stopped"
	ProxyPhaseFailed      ProxyPhase = "Failed"
)

// ProxyStatus defines the observed state of Proxy.
type ProxyStatus struct {
	// Start time of the proxy.
	StartTimestamp *metav1.Time `json:"startTimestamp,omitempty"`

	// IPv4/6 address string of the proxy. If provided in the spec, this will be the same as
	// the addressRef data.
	// +optional
	Address string `json:"address,omitempty"`

	// Phase of the proxy.
	// Examples: "Pending", "Running", "Failed", etc.
	Phase ProxyPhase `json:"phase,omitempty"`

	// MachineID of the proxy.
	// Used to identify the proxy instance in the infrastructure provider.
	// +optional
	MachineID string `json:"machineID,omitempty"`

	// Status of the proxy.
	// +optional
	Status string `json:"status,omitempty"`
}

var _ resource.StatusSubResource = &ProxyStatus{}

func (ps *ProxyStatus) SubResourceName() string {
	return "status"
}

func (ps *ProxyStatus) CopyTo(parent resource.ObjectWithStatusSubResource) {
	parent.(*Proxy).Status = *ps
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:subresource:log

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Proxy is the Schema for the proxies API.
type Proxy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ProxySpec   `json:"spec,omitempty"`
	Status ProxyStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &Proxy{}
	_ resource.Object                      = &Proxy{}
	_ resource.ObjectWithStatusSubResource = &Proxy{}
	_ rest.SingularNameProvider            = &Proxy{}
)

func (p *Proxy) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *Proxy) NamespaceScoped() bool {
	return false
}

func (p *Proxy) New() runtime.Object {
	return &Proxy{}
}

func (p *Proxy) NewList() runtime.Object {
	return &ProxyList{}
}

func (p *Proxy) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    GroupVersion.Group,
		Version:  GroupVersion.Version,
		Resource: "proxies",
	}
}

func (p *Proxy) IsStorageVersion() bool {
	return true
}

func (p *Proxy) GetSingularName() string {
	return "proxy"
}

func (p *Proxy) GetStatus() resource.StatusSubResource {
	return &p.Status
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ProxyList contains a list of Proxy objects.
type ProxyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Proxy `json:"items"`
}

var _ resource.ObjectList = &ProxyList{}

func (pl *ProxyList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

func init() {
	SchemeBuilder.Register(&Proxy{}, &ProxyList{})
}

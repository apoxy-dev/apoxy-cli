package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
)

const (
	ProxyFinalizer = "proxy.core.apoxy.dev/finalizer"
)

// InfraProvider defines the infrastructure provider where the proxy will be deployed.
type InfraProvider string

const (
	// InfraProviderCloud is the cloud provider.
	// This provider deploys proxies within Apoxy Edge.
	InfraProviderCloud InfraProvider = "cloud"
	// InfraProviderKubernetes is the kubernetes provider.
	// This provider is used to deploy the proxy as a kubernetes pod.
	InfraProviderKubernetes InfraProvider = "kubernetes"
	// InfraProviderUnmanaged is the unmanaged provider.
	// This provider is used for proxies that are deployed by users themselves and
	// are not managed by Apoxy Control Plane.
	InfraProviderUnmanaged InfraProvider = "unmanaged"
)

// ProxySpec defines the desired specification of a Proxy.
type ProxySpec struct {
	// Provider is the infrastructure provider where the proxy will be deployed.
	// Defaults to "cloud" provider.
	Provider InfraProvider `json:"provider,omitempty"`

	// Locations is the list of locations where the proxy will be deployed:
	// * cloud provider:
	//  - global: Deploy the proxy in the global network.
	//  - <region>: Deploy the proxy in the specified region (e.g "europe")
	//  - <pop>: Deploy the proxy in the specified point of presence.
	// * kubernetes provider - The list of kubernetes clusters where the proxy will be deployed.
	// * unmanaged provider - Ignored.
	Locations []string `json:"locations,omitempty"`

	// Config is the Starlark configuration for the proxy in the txtar format.
	Config string `json:"config,omitempty"`
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
	// Phase of the proxy.
	// Examples: "Pending", "Running", "Failed", etc.
	Phase ProxyPhase `json:"phase,omitempty"`

	// Reason for the current phase.
	// +optional
	Reason string `json:"reason,omitempty"`

	// IPv4/v6 addresses of the proxy.
	// +optional
	IPs []string `json:"ips,omitempty"`

	// PoPs are the points of presence where the proxy is deployed.
	// +optional
	PoPs []string `json:"pops,omitempty"`
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

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

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
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
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

package v1alpha

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Backend configures a backend (upstream) endpoint for a Proxy.
type Backend struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BackendSpec   `json:"spec,omitempty"`
	Status BackendStatus `json:"status,omitempty"`
}

// BackendProto defines the protocol to use for the backend.
// +kubebuilder:validation:Enum="";tls;h2;h2c
type BackendProto string

const (
	// BackendProtoTLS allows requests to be forwarded to the backend over TLS.
	// Should be used for HTTP/1.1 over TLS.
	BackendProtoTLS BackendProto = "tls"

	// BackendProtoH2 allows requests to be forwarded to the backend over HTTP/2.
	// Should be used for HTTP/2 over TLS.
	BackendProtoH2 BackendProto = "h2"

	// BackendProtoH2C allows requests to be forwarded to the backend over HTTP/2 cleartext.
	BackendProtoH2C BackendProto = "h2c"
)

type BackendSpec struct {
	// List of endpoints to connect to.
	Endpoints []BackendEndpoint `json:"endpoints"`

	// Protocol defines the protocol to use for the backend.
	Protocols []BackendProto `json:"protocols"`
}

type BackendEndpoint struct {
	// FQDN is the fully qualified domain name of the endpoint.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9]))*$`
	// +optional
	FQDN string `json:"fqdn,omitempty"`

	// Endpoint defined as an IPv4/IPv6 address.
	// +kubebuilder:validation:Format=ipv4
	// +kubebuilder:validation:Format=ipv6
	// +optional
	IP string `json:"ip,omitempty"`
}

type BackendStatus struct {
	// Conditions describe the current conditions of the Backend.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

var _ resource.StatusSubResource = &BackendStatus{}

func (ps *BackendStatus) SubResourceName() string {
	return "status"
}

func (ps *BackendStatus) CopyTo(parent resource.ObjectWithStatusSubResource) {
	parent.(*Backend).Status = *ps
}

var (
	_ runtime.Object                       = &Backend{}
	_ resource.Object                      = &Backend{}
	_ resource.ObjectWithStatusSubResource = &Backend{}
	_ rest.SingularNameProvider            = &Backend{}
)

func (p *Backend) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *Backend) NamespaceScoped() bool {
	return false
}

func (p *Backend) New() runtime.Object {
	return &Backend{}
}

func (p *Backend) NewList() runtime.Object {
	return &BackendList{}
}

func (p *Backend) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "backends",
	}
}

func (p *Backend) IsStorageVersion() bool {
	return true
}

func (p *Backend) GetSingularName() string {
	return "backend"
}

func (p *Backend) GetStatus() resource.StatusSubResource {
	return &p.Status
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// BackendList contains a list of Backend objects.
type BackendList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Backend `json:"items"`
}

var _ resource.ObjectList = &BackendList{}

func (pl *BackendList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

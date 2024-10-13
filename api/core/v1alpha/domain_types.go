package v1alpha

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
)

const (
	DomainFinalizer = "domain.core.apoxy.dev/finalizer"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type Domain struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec DomainSpec `json:"spec,omitempty"`

	Status DomainStatus `json:"status,omitempty"`
}

type DomainSpec struct {
	// Zone is the zone of the domain.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Zone string `json:"zone"`

	// Name is the name of the domain record.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?$`
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Type is the type of the domain record.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=A,AAAA,CNAME,TXT,ALIAS
	Type string `json:"type"`

	// TTL is the time-to-live of the domain record.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Required
	// +kubebuilder:default=300
	// +kubebuilder:validation:Format=int32
	// +kubebuilder:validation:Maximum=3600
	TTL int32 `json:"ttl"`

	// Value is the value of the domain record.
	// +kubebuilder:validation:Required
	Value DomainValue `json:"value"`

	// DNSOnly is a flag to indicate if the domain represents only a DNS record
	// and no traffic is routed via Apoxy.
	// +kubebuilder:validation:Default=false
	// +optional
	DNSOnly bool `json:"dnsOnly,omitempty"`
}

type DomainTargetRef struct {
	// Group is the API Group of the target object.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Group string `json:"group"`

	// Kind is the kind of the target object.
	// Currently supports Proxy, EdgeFunction, TunnelEndpoint kinds.
	// +kubebuilder:validation:Required
	Kind string `json:"kind"`

	// Name is the name of the target object.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?$`
	Name string `json:"name"`
}

type DomainValue struct {
	// IP is the IP address of the domain record.
	// Applicable for A and AAAA records.
	// +kubebuilder:validation:MaxItems=20
	IP []string `json:"ip,omitempty"`

	// FQDN is the fully qualified domain name of the domain record.
	// Applicable for CNAME records.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?$`
	FQDN *string `json:"fqdn,omitempty"`

	// Text is the text of the domain record.
	// Applicable for TXT records and when DNSOnly is set to true.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Text *string `json:"text,omitempty"`

	// ProxyRef is the reference to the proxy object.
	// Applicable for ALIAS records and when DNSOnly is set to false.
	// +optional
	TargetRef *DomainTargetRef `json:"targetRef,omitempty"`
}

// DomainPhase is the phase of the domain.
type DomainPhase string

const (
	// DomainPhasePending is the pending phase of the domain.
	// This is the initial phase of the domain.
	DomainPhasePending = "Pending"
	// DomainPhaseAllocated is the allocated phase of the domain.
	DomainPhaseAllocated = "Allocated"
	// DomainPhaseAttached is the state of the domain when it is attached to
	// one or more addresses. If there are no addresses found, the domain
	// will be stuck in either the pending or allocated phase.
	DomainPhaseAttached = "Attached"
	// DomainPhaseError is the state of the domain when an unrecoverable
	// error has occured.
	DomainPhaseError = "Error"
)

type DomainStatus struct {
	// Phase of the domain.
	Phase DomainPhase `json:"phase,omitempty"`

	// Status of the domain.
	// +optional
	Status string `json:"status,omitempty"`
}

var _ resource.StatusSubResource = &DomainStatus{}

func (as *DomainStatus) SubResourceName() string {
	return "status"
}

func (as *DomainStatus) CopyTo(parent resource.ObjectWithStatusSubResource) {
	parent.(*Domain).Status = *as
}

var _ runtime.Object = &Domain{}
var _ resource.Object = &Domain{}
var _ resource.ObjectWithStatusSubResource = &Domain{}
var _ rest.SingularNameProvider = &Domain{}

func (a *Domain) GetObjectMeta() *metav1.ObjectMeta {
	return &a.ObjectMeta
}

func (a *Domain) NamespaceScoped() bool {
	return false
}

func (a *Domain) New() runtime.Object {
	return &Domain{}
}

func (a *Domain) NewList() runtime.Object {
	return &DomainList{}
}

func (a *Domain) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "domains",
	}
}

func (a *Domain) IsStorageVersion() bool {
	return true
}

func (a *Domain) GetSingularName() string {
	return "domain"
}

func (a *Domain) GetStatus() resource.StatusSubResource {
	return &a.Status
}

//+kubebuilder:object:root=true

// DomainList is a list of Domain resources.
type DomainList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Domain `json:"items"`
}

var _ resource.ObjectList = &DomainList{}

func (pl *DomainList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

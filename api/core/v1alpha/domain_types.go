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

// Domain is the Schema for the domains API.
type Domain struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec DomainSpec `json:"spec,omitempty"`

	Status DomainStatus `json:"status,omitempty"`
}

// DomainStyle is the style of the domain.
type DomainStyle string

const (
	// DomainStyleApoxy is an Apoxy managed DNS provider.
	// The apoxydns.com nameservers will be configured.
	// Announcing nameservers will be set in the DomainStatus.
	// Users may choose to CNAME the provided hostnames to {hostname}.apoxydns.com.
	// For example, if the hostname is "foo.com", the user may CNAME "foo.com" to
	// "foo.com.apoxydns.com".
	// This is the default configuration.
	DomainStyleApoxy = "apoxy"
	// DomainStyleMagic is an Apoxy Cloud magic domain.
	// A subdomain on apoxy.io will be allocated and announced.
	DomainStyleMagic = "magic"
	// TODO(mattward): Other potentially supported DomainStyles include
	// DomainStyleRoute53 or DomainStyleNS1 where the domain is managed by
	// Route53 or NS1, for example.
)

type DomainSpec struct {
	// Selector is a label selector used to find healthy proxies for the domain.
	Selector metav1.LabelSelector `json:"selector"`

	// Style of the domain.
	// See style constants for more information.
	// Defaults to DomainStyleApoxy.
	// +optional
	Style DomainStyle `json:"style,omitempty"`

	// A list of hostnames.
	// +optional
	Hostnames []string `json:"hostnames,omitempty"`

	// The magic key that was allocated if this domain is DomainStyleMagic.
	// When the domain is DomainPhaseAttached, {magicKey}.apoxy.io will be available.
	// This is immutable and cannot be changed because it is allocated by the
	// Apoxy Cloud magic domain manager.
	// +optional
	MagicKey string `json:"magicKey,omitempty"`
}

// DomainPhase is the phase of the domain.
type DomainPhase string

const (
	// DomainPhasePending is the pending phase of the domain.
	// This is the initial phase of the domain.
	DomainPhasePending = "Pending"
	// DomainPhaseAllocated is the allocated phase of the domain.
	// This is the phase of the domain when it is allocated a magic domain
	// if the style of this domain is DomainStyleMagic.
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

func init() {
	SchemeBuilder.Register(&Domain{}, &DomainList{})
}

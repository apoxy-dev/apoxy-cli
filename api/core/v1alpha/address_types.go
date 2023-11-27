package v1alpha

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
)

const (
	AddressFinalizer = "address.core.apoxy.dev/finalizer"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Address is the Schema for the addresses API.
type Address struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec AddressSpec `json:"spec,omitempty"`

	Status AddressStatus `json:"status,omitempty"`
}

// DeletePolicy is the delete policy of the address.
type DeletePolicy string

const (
	// DeletePolicyDelete is the delete policy that will delete the address
	// when the last Address is detached from the address.
	DeletePolicyDelete = "Delete"
	// DeletePolicyRetain is the delete policy that will retain the address
	// when the last Address is detached from the address.
	DeletePolicyRetain = "Retain"
)

type AddressSpec struct {
	// Provider of the address.
	// See provider constants for more information.
	Provider InfraProvider `json:"provider,omitempty"`

	// IPv4/IPv6 address string.
	// This is immutable and cannot be changed.
	// Allocated by the IP address manager.
	IP string `json:"ip,omitempty"`

	// Location of the address.
	// Examples: "us-east1", "us-west1", etc.
	// If not provided, the address is global (anycast) for cloud.
	// +optional
	Location string `json:"location,omitempty"`

	// DeletePolicy of the address.
	// See delete policy constants for more information.
	// Defaults to DeletePolicyDelete.
	// +optional
	DeletePolicy DeletePolicy `json:"deletePolicy,omitempty"`
}

// AddressPhase is the phase of the address.
type AddressPhase string

const (
	// AddressPhasePending is the pending phase of the address.
	// This is the initial phase of the address.
	AddressPhasePending = "Pending"
	// AddressPhaseAllocated is the allocated phase of the address.
	// This is the phase of the address when it is allocated by the IP address manager
	// and ready to be attached to one or more proxies.
	AddressPhaseAllocated = "Allocated"
	// AddressPhaseAttached is the state of the address when it is attached to
	// one or more proxies. If there are no proxies attached to the address,
	// the address will either return to the Allocated phase or be deleted
	// depending on the address provider and deletion policy.
	AddressPhaseAttached = "Attached"
)

type AddressStatus struct {
	// Phase of the address.
	Phase AddressPhase `json:"phase,omitempty"`

	// Status of the address.
	// +optional
	Status string `json:"status,omitempty"`
}

var _ resource.StatusSubResource = &AddressStatus{}

func (as *AddressStatus) SubResourceName() string {
	return "status"
}

func (as *AddressStatus) CopyTo(parent resource.ObjectWithStatusSubResource) {
	parent.(*Address).Status = *as
}

var _ runtime.Object = &Address{}
var _ resource.Object = &Address{}
var _ resource.ObjectWithStatusSubResource = &Address{}
var _ rest.SingularNameProvider = &Address{}

func (a *Address) GetObjectMeta() *metav1.ObjectMeta {
	return &a.ObjectMeta
}

func (a *Address) NamespaceScoped() bool {
	return false
}

func (a *Address) New() runtime.Object {
	return &Address{}
}

func (a *Address) NewList() runtime.Object {
	return &AddressList{}
}

func (a *Address) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    GroupVersion.Group,
		Version:  GroupVersion.Version,
		Resource: "addresses",
	}
}

func (a *Address) IsStorageVersion() bool {
	return true
}

func (a *Address) GetSingularName() string {
	return "address"
}

func (a *Address) GetStatus() resource.StatusSubResource {
	return &a.Status
}

//+kubebuilder:object:root=true

// AddressList is a list of Address resources.
type AddressList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Address `json:"items"`
}

var _ resource.ObjectList = &AddressList{}

func (pl *AddressList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

func init() {
	SchemeBuilder.Register(&Address{}, &AddressList{})
}

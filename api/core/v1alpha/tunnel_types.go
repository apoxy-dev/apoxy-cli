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
// +kubebuilder:subresource:log

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TunnelNode represents a node in the tunnel network.
type TunnelNode struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TunnelNodeSpec   `json:"spec,omitempty"`
	Status TunnelNodeStatus `json:"status,omitempty"`
}

type TunnelNodeSpec struct {
	Peers []TunnelRef `json:"peers,omitempty"`
}

type TunnelRef struct {
	// TunnelNodeRef is a reference to an individual TunnelNode.
	TunnelNodeRef *TunnelNodeRef `json:"tunnelNodeRef,omitempty"`
	// LabelSelector is a label selector to dynamically select multiple TunnelNode objects.
	LabelSelector *metav1.LabelSelector `json:"labelSelector,omitempty"`
}

type TunnelNodeRef struct {
	// Name of the tunnel node.
	Name string `json:"name,omitempty"`
}

type TunnelNodePhase string

const (
	// NodePhaseInitializing is the phase for a node that is being setup
	// before it moves into "Ready" (to accept connections from peers and
	// relay traffic for them) or "Failed" (if it fails to setup).
	NodePhaseInitializing TunnelNodePhase = "Initializing"
	// NodePhaseReady
	NodePhaseReady TunnelNodePhase = "Ready"
	// NodePhaseFailed
	NodePhaseFailed TunnelNodePhase = "Failed"
)

type TunnelNodeStatus struct {
	// Phase of the node.
	Phase TunnelNodePhase `json:"phase,omitempty"`

	// Conditions of the tunnel node.
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Public key of the node (base64 encoded).
	PublicKey string `json:"publicKey,omitempty"`

	// External address of the node or address of the NAT hole punched.
	ExternalAddress string `json:"externalAddress,omitempty"`

	// Internal address of the node. Always a /96 IPv6 address.
	InternalAddress string `json:"internalAddress,omitempty"`

	// Last time the tunnel node configuration was synced.
	// +optional
	LastSynced *metav1.Time `json:"lastSynced,omitempty"`

	// Epoch is an opaque value that represents the current run of the tunnel node controller.
	// TunnelPeerOffers created for this node will have core.apoxy.dev/tunnelnode-epoch=<epoch>
	// set to this value.
	Epoch int64 `json:"epoch"`
}

var _ resource.StatusSubResource = &TunnelNodeStatus{}

func (ps *TunnelNodeStatus) SubResourceName() string {
	return "status"
}

func (ps *TunnelNodeStatus) CopyTo(parent resource.ObjectWithStatusSubResource) {
	parent.(*TunnelNode).Status = *ps
}

var (
	_ runtime.Object                       = &TunnelNode{}
	_ resource.Object                      = &TunnelNode{}
	_ resource.ObjectWithStatusSubResource = &TunnelNode{}
	_ rest.SingularNameProvider            = &TunnelNode{}
)

func (p *TunnelNode) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *TunnelNode) NamespaceScoped() bool {
	return false
}

func (p *TunnelNode) New() runtime.Object {
	return &TunnelNode{}
}

func (p *TunnelNode) NewList() runtime.Object {
	return &TunnelNodeList{}
}

func (p *TunnelNode) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "tunnelnodes",
	}
}

func (p *TunnelNode) IsStorageVersion() bool {
	return true
}

func (p *TunnelNode) GetSingularName() string {
	return "tunnelnode"
}

func (p *TunnelNode) GetStatus() resource.StatusSubResource {
	return &p.Status
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TunnelNodeList contains a list of TunnelNode objects.
type TunnelNodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TunnelNode `json:"items"`
}

var _ resource.ObjectList = &TunnelNodeList{}

func (pl *TunnelNodeList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:subresource:log

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TunnelPeerOffer is a connection between two tunnel peers.
type TunnelPeerOffer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TunnelPeerOfferSpec   `json:"spec,omitempty"`
	Status TunnelPeerOfferStatus `json:"status,omitempty"`
}

type ICEOffer struct {
	// Candidates is a list of ICE candidates in a string representation.
	Candidates []string `json:"candidates,omitempty"`

	// ice-ufrag (username fragment) of the ICE connection.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?$`
	Ufrag string `json:"ufrag,omitempty"`

	// ice-pwd (password) of the ICE connection.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?$`
	Password string `json:"password,omitempty"`
}

type TunnelPeerOfferSpec struct {
	// RemoteTunnelNodeName is the name of the remote tunnel node that this offer is for.
	RemoteTunnelNodeName string `json:"remoteTunnelNodeName,omitempty"`

	// Offer is the ICE connection information.
	// +optional
	Offer *ICEOffer `json:"iceOffer,omitempty"`
}

type TunnelPeerOfferPhase string

const (
	TunnelPeerOfferPhaseConnecting TunnelPeerOfferPhase = "Connecting"
	TunnelPeerOfferPhaseConnected  TunnelPeerOfferPhase = "Connected"
	TunnelPeerOfferPhaseFailed     TunnelPeerOfferPhase = "Failed"
)

type TunnelPeerOfferStatus struct {
	// Phase is the current aggregate phase of the tunnel peer offer.
	// It may be represented by one or more conditions.
	Phase TunnelPeerOfferPhase `json:"phase,omitempty"`

	// Conditions is a list of conditions that apply to the tunnel peer offer.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

var _ resource.StatusSubResource = &TunnelPeerOfferStatus{}

func (ps *TunnelPeerOfferStatus) SubResourceName() string {
	return "status"
}

func (ps *TunnelPeerOfferStatus) CopyTo(parent resource.ObjectWithStatusSubResource) {
	parent.(*TunnelPeerOffer).Status = *ps
}

var (
	_ runtime.Object                       = &TunnelPeerOffer{}
	_ resource.Object                      = &TunnelPeerOffer{}
	_ resource.ObjectWithStatusSubResource = &TunnelPeerOffer{}
	_ rest.SingularNameProvider            = &TunnelPeerOffer{}
)

func (p *TunnelPeerOffer) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *TunnelPeerOffer) NamespaceScoped() bool {
	return false
}

func (p *TunnelPeerOffer) New() runtime.Object {
	return &TunnelPeerOffer{}
}

func (p *TunnelPeerOffer) NewList() runtime.Object {
	return &TunnelPeerOfferList{}
}

func (p *TunnelPeerOffer) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "tunnelpeeroffers",
	}
}

func (p *TunnelPeerOffer) IsStorageVersion() bool {
	return true
}

func (p *TunnelPeerOffer) GetSingularName() string {
	return "tunnelpeeroffer"
}

func (p *TunnelPeerOffer) GetStatus() resource.StatusSubResource {
	return &p.Status
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TunnelPeerOfferList contains a list of TunnelPeerOffer objects.
type TunnelPeerOfferList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TunnelPeerOffer `json:"items"`
}

var _ resource.ObjectList = &TunnelPeerOfferList{}

func (pl *TunnelPeerOfferList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

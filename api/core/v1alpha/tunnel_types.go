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
	// Public key of the node.
	PubKey string `json:"pubKey,omitempty"`

	// External address of the node or address of the NAT hole punched.
	ExternalAddress string `json:"externalAddress,omitempty"`

	// Internal address of the node. Always a /96 IPv6 address.
	InternalAddress string `json:"internalAddress,omitempty"`

	// CIDRs that the node will be relaying traffic for.
	// These are endpoints downstream of the node for which the node is acting
	// as a gateway.
	ForwardedFor []string `json:"forwardedFor,omitempty"`
}

type NodePhase string

const (
	// NodePhasePending is the phase for a node that is being setup
	// before it moves into "Ready" (to accept connections from peers and
	// relay traffic for them) or "Failed" (if it fails to setup).
	NodePhasePending NodePhase = "Pending"
	// NodePhaseReady
	NodePhaseReady NodePhase = "Ready"
	// NodePhaseFailed
	NodePhaseFailed NodePhase = "Failed"
)

type PeerPhase string

const (
	// PeerPhaseWaiting is the phase for a peer that is waiting for the node
	// to accept its connection.
	PeerPhaseWaiting PeerPhase = "Waiting"
	// PeerPhaseConnected is the phase for a peer that is connected to the node.
	PeerPhaseConnected PeerPhase = "Connected"
	// PeerPhaseFailed is the phase for a peer that failed to connect to the node.
	// This phase is used when the node is unable to accept the peer's connection.
	PeerPhaseFailed PeerPhase = "Failed"
)

type PeerStatus struct {
	// Public key of the peer.
	PubKey string `json:"pubKey,omitempty"`

	// ExternalAddress of the peer.
	// This is the address of the peer that is directly accessible
	// via host network.
	ExternalAddress string `json:"externalAddress,omitempty"`

	// InternalAddress of the peer.
	// This is the address of the peer on the tunnel overlay network.
	InternalAddress string `json:"internalAddress,omitempty"`

	// Phase of the peer.
	Phase PeerPhase `json:"phase,omitempty"`
}

type TunnelNodeStatus struct {
	// Phase of the node.
	Phase NodePhase `json:"phase,omitempty"`

	// PeerStatuses is a list of statuses of the peers that the node is connected to.
	PeerStatuses []PeerStatus `json:"peerStatuses,omitempty"`
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

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
}

type AgentStatus struct {
	// Name is the name of the agent. Must be unique within the tunnel node.
	Name string `json:"name,omitempty"`

	// ConnectedAt is the time when the agent was connected to the tunnel node.
	ConnectedAt *metav1.Time `json:"connectedAt,omitempty"`

	// Overlay address of the agent that is routable on the internal Apoxy network.
	PrivateAddress string `json:"privateAddress,omitempty"`

	// Address of the agent (publicly routable) that it has connected with to establish a tunnel.
	AgentAddress string `json:"agentAddress,omitempty"`
}

type TunnelNodeStatus struct {
	// One or more addresses used by agents to establish a tunnel.
	Addresses []string `json:"addresses,omitempty"`

	// Credentials for the tunnel node proxy.
	Credentials string `json:"credentials,omitempty"`

	// Agents is a list of agents connected to the tunnel node.
	Agents []AgentStatus `json:"agents,omitempty"`
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

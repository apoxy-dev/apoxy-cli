package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
)

type ProxySetSpec struct {
	// Selector is a label selector that matches Proxy objects that will
	// receive this deployment configuration.
	// Immutable field.
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// Starlark config that applies to all proxies in the set.
	// Immutable field.
	Config string `json:"config,omitempty"`
}

type ProxySetStatus struct {
	// Total number of non-terminated proxies targeted by this deployment.
	Count int32 `json:"count,omitempty"`

	// ReadyCount is the number of proxies that have latest configuration
	// applied and are ready to serve traffic.
	ReadyCount int32 `json:"readyCount,omitempty"`
}

var _ resource.StatusSubResource = &ProxySetStatus{}

func (ps *ProxySetStatus) SubResourceName() string {
	return "status"
}

func (ps *ProxySetStatus) CopyTo(parent resource.ObjectWithStatusSubResource) {
	parent.(*ProxySet).Status = *ps
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ProxySet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ProxySetSpec   `json:"spec,omitempty"`
	Status ProxySetStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &ProxySet{}
	_ resource.Object                      = &ProxySet{}
	_ resource.ObjectWithStatusSubResource = &ProxySet{}
	_ rest.SingularNameProvider            = &ProxySet{}
)

func (p *ProxySet) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *ProxySet) NamespaceScoped() bool {
	return false
}

func (p *ProxySet) New() runtime.Object {
	return &ProxySet{}
}

func (p *ProxySet) NewList() runtime.Object {
	return &ProxySetList{}
}

func (p *ProxySet) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "proxysets",
	}
}

func (p *ProxySet) IsStorageVersion() bool {
	return true
}

func (p *ProxySet) GetSingularName() string {
	return "proxyset"
}

func (p *ProxySet) GetStatus() resource.StatusSubResource {
	return &p.Status
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ProxySetList contains a list of ProxySet objects.
type ProxySetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ProxySet `json:"items"`
}

var _ resource.ObjectList = &ProxySetList{}

func (pl *ProxySetList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
)

type ProxyDeploymentStrategyType string

const (
	RollingUpdate ProxyDeploymentStrategyType = "RollingUpdate"
)

type RollingUpdateDeployment struct {
	// MaxUnavailable is the maximum number of proxies that can be unavailable
	// during the update process. Value can be an absolute number (ex: 5) or a
	// percentage of total proxies at the start of the update process (ex: 10%).
	// Absolute number is calculated from percentage by rounding down.
	MaxUnavailable *intstr.IntOrString `json:"maxUnavailable,omitempty"`

	// MaxSurge is the maximum number of proxies that can be scheduled above the
	// desired number of proxies. Value can be an absolute number (ex: 5) or a
	// percentage of total proxies at the start of the update process (ex: 10%).
	// Absolute number is calculated from percentage by rounding up.
	// Not applicable for the "unmanaged".
	// +optional
	MaxSurge *intstr.IntOrString `json:"maxSurge,omitempty"`
}

type ProxyDeploymentStrategy struct {
	Type ProxyDeploymentStrategyType `json:"type,omitempty"`

	// Rolling update strategy parameters.
	// This field is required if the Type is RollingUpdate.
	// +optional
	RollingUpdate *RollingUpdateDeployment `json:"rollingUpdate,omitempty"`
}

type ProxyDeploymentSpec struct {
	// Selector is a label selector that matches Proxy objects that will
	// receive this deployment configuration.
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// Config is the Starlark configuration that will be applied to
	// the matching proxies.
	Config string `json:"config,omitempty"`

	// Strategy describes how to deploy the configuration to the proxies.
	Strategy ProxyDeploymentStrategy `json:"strategy,omitempty"`
}

type ProxyDeploymentStatus struct {
	// Total number of non-terminated proxies targeted by this deployment.
	Count int32 `json:"count,omitempty"`

	// ReadyCount is the number of proxies that have latest configuration
	// applied and are ready to serve traffic.
	ReadyCount int32 `json:"readyCount,omitempty"`
}

var _ resource.StatusSubResource = &ProxyDeploymentStatus{}

func (ps *ProxyDeploymentStatus) SubResourceName() string {
	return "status"
}

func (ps *ProxyDeploymentStatus) CopyTo(parent resource.ObjectWithStatusSubResource) {
	parent.(*ProxyDeployment).Status = *ps
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ProxyDeployment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ProxyDeploymentSpec   `json:"spec,omitempty"`
	Status ProxyDeploymentStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object                       = &ProxyDeployment{}
	_ resource.Object                      = &ProxyDeployment{}
	_ resource.ObjectWithStatusSubResource = &ProxyDeployment{}
	_ rest.SingularNameProvider            = &ProxyDeployment{}
)

func (p *ProxyDeployment) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *ProxyDeployment) NamespaceScoped() bool {
	return false
}

func (p *ProxyDeployment) New() runtime.Object {
	return &ProxyDeployment{}
}

func (p *ProxyDeployment) NewList() runtime.Object {
	return &ProxyDeploymentList{}
}

func (p *ProxyDeployment) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "proxydeployments",
	}
}

func (p *ProxyDeployment) IsStorageVersion() bool {
	return true
}

func (p *ProxyDeployment) GetSingularName() string {
	return "proxydeployment"
}

func (p *ProxyDeployment) GetStatus() resource.StatusSubResource {
	return &p.Status
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ProxyDeploymentList contains a list of ProxyDeployment objects.
type ProxyDeploymentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ProxyDeployment `json:"items"`
}

var _ resource.ObjectList = &ProxyDeploymentList{}

func (pl *ProxyDeploymentList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type GatewayClass struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec gwapiv1.GatewayClassSpec `json:"spec,omitempty"`

	Status gwapiv1.GatewayClassStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object            = &GatewayClass{}
	_ resource.Object           = &GatewayClass{}
	_ rest.SingularNameProvider = &GatewayClass{}
)

func (p *GatewayClass) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *GatewayClass) NamespaceScoped() bool {
	return false
}

func (p *GatewayClass) New() runtime.Object {
	return &GatewayClass{}
}

func (p *GatewayClass) NewList() runtime.Object {
	return &GatewayClassList{}
}

func (p *GatewayClass) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "gatewayclasses",
	}
}

func (p *GatewayClass) IsStorageVersion() bool {
	return true
}

func (p *GatewayClass) GetSingularName() string {
	return "gatewayclass"
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type GatewayClassList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GatewayClass `json:"items"`
}

var _ resource.ObjectList = &GatewayClassList{}

func (pl *GatewayClassList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

// +kubebuilder:object:root=true

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type Gateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec gwapiv1.GatewaySpec `json:"spec,omitempty"`

	Status gwapiv1.GatewayStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object            = &Gateway{}
	_ resource.Object           = &Gateway{}
	_ rest.SingularNameProvider = &Gateway{}
)

func (p *Gateway) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *Gateway) NamespaceScoped() bool {
	return false
}

func (p *Gateway) New() runtime.Object {
	return &Gateway{}
}

func (p *Gateway) NewList() runtime.Object {
	return &GatewayList{}
}

func (p *Gateway) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "gateways",
	}
}

func (p *Gateway) IsStorageVersion() bool {
	return true
}

func (p *Gateway) GetSingularName() string {
	return "gateway"
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type GatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Gateway `json:"items"`
}

var _ resource.ObjectList = &GatewayList{}

func (pl *GatewayList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

// +kubebuilder:object:root=true

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type HTTPRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec gwapiv1.HTTPRouteSpec `json:"spec,omitempty"`

	Status gwapiv1.HTTPRouteStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object            = &HTTPRoute{}
	_ resource.Object           = &HTTPRoute{}
	_ rest.SingularNameProvider = &HTTPRoute{}
)

func (p *HTTPRoute) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *HTTPRoute) NamespaceScoped() bool {
	return false
}

func (p *HTTPRoute) New() runtime.Object {
	return &HTTPRoute{}
}

func (p *HTTPRoute) NewList() runtime.Object {
	return &HTTPRouteList{}
}

func (p *HTTPRoute) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "httproutes",
	}
}

func (p *HTTPRoute) IsStorageVersion() bool {
	return true
}

func (p *HTTPRoute) GetSingularName() string {
	return "httproute"
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type HTTPRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HTTPRoute `json:"items"`
}

var _ resource.ObjectList = &HTTPRouteList{}

func (pl *HTTPRouteList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

// +kubebuilder:object:root=true

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type GRPCRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec gwapiv1.GRPCRouteSpec `json:"spec,omitempty"`

	Status gwapiv1.GRPCRouteStatus `json:"status,omitempty"`
}

var (
	_ runtime.Object            = &GRPCRoute{}
	_ resource.Object           = &GRPCRoute{}
	_ rest.SingularNameProvider = &GRPCRoute{}
)

func (p *GRPCRoute) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *GRPCRoute) NamespaceScoped() bool {
	return false
}

func (p *GRPCRoute) New() runtime.Object {
	return &GRPCRoute{}
}

func (p *GRPCRoute) NewList() runtime.Object {
	return &GRPCRouteList{}
}

func (p *GRPCRoute) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    SchemeGroupVersion.Group,
		Version:  SchemeGroupVersion.Version,
		Resource: "grpcroutes",
	}
}

func (p *GRPCRoute) IsStorageVersion() bool {
	return true
}

func (p *GRPCRoute) GetSingularName() string {
	return "grpcroute"
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type GRPCRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GRPCRoute `json:"items"`
}

var _ resource.ObjectList = &GRPCRouteList{}

func (pl *GRPCRouteList) GetListMeta() *metav1.ListMeta {
	return &pl.ListMeta
}

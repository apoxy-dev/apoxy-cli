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
	// Owner is the owner of the domain.
	// +kubebuilder:validation:Required
	Owner DomainOwner `json:"owner"`

	// The list of subdomains nested under the domain.
	// Allows for wildcard subdomains.
	// +kubebuilder:validation:MaxItems=50
	Subdomains []string `json:"subdomains,omitempty"`

	// Target of the domain.
	// +kubebuilder:validation:Required
	Target DomainTargetSpec `json:"target"`

	// SSL configuration for the domain.
	SSLSpec *DomainSSLSpec `json:"ssl,omitempty"`
}

type DomainOwner struct {
	// If zone is specified, the Domain is owned by the
	// zone managed by Apoxy (either user zone or Apoxy built-in zone).
	Zone *ZoneDomainOwner `json:"zone,omitempty"`

	// If external is specified, the Domain is owned by an external entity.
	// As Apoxy does not have control over the zone, the user is responsible
	// for creating the necessary records in the zone to point to the Apoxy
	// nameservers as well as required validation records.
	External *ExternalDomainOwner `json:"external,omitempty"`
}

type ZoneDomainOwner struct {
	// Zone is the name of the zone.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?$`
	Zone string `json:"zone"`
}

type ExternalDomainOwner struct {
}

type DomainTargetSpec struct {
	// Represents targets specified via DNS.
	DNS *DomainTargetDNS `json:"dns,omitempty"`

	// Represent a target specified via a reference to another object
	// within Apoxy (e.g. Proxy, EdgeFunction, TunnelEndpoint).
	Ref *DomainTargetRef `json:"ref,omitempty"`
}

type DomainTargetDNSType string

const (
	DomainTargetDNSTypeA     = "A"
	DomainTargetDNSTypeAAAA  = "AAAA"
	DomainTargetDNSTypeCNAME = "CNAME"
	DomainTargetDNSTypeTXT   = "TXT"
)

type DomainTargetDNS struct {
	// IP address of the target.
	// Setting this field will create an A/AAAA record.
	// Cannot be set with FQDN.
	// +optional
	IP string `json:"ip,omitempty"`

	// IPs is the list of IP addresses of the target.
	// When both IP and IPs are specified, IP will be appended to IPs.
	// Setting this field will create an A/AAAA record (multi-value).
	// Cannot be set with FQDN.
	// +kubebuilder:validation:MaxItems=20
	// +optional
	IPs []string `json:"ips,omitempty"`

	// FQDN is the fully qualified domain name of the target.
	// Setting this field will create an CNAME record.
	// Cannot be set with IP or IPs.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?$`
	FQDN *string `json:"fqdn,omitempty"`

	// Text represent a TXT record value.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Text *string `json:"text,omitempty"`

	// DNSOnly is a flag to indicate if the domain represents only a DNS record
	// and no traffic is routed via Apoxy.
	// +kubebuilder:validation:Default=false
	// +optional
	DNSOnly bool `json:"dnsOnly,omitempty"`

	// TTL is the time-to-live of the domain record.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Required
	// +kubebuilder:default=20
	// +kubebuilder:validation:Format=int32
	// +kubebuilder:validation:Maximum=3600
	// +optional
	TTL *int32 `json:"ttl"`
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

type DomainSSLSpec struct {
	// The Certificate Authority used to issue the SSL certificate.
	// Currently supports "letsencrypt".
	// +optional
	CertificateAuthority string `json:"certificateAuthority,omitempty"`
}

// DomainPhase is the phase of the domain.
type DomainPhase string

const (
	// DomainPhasePending is the pending phase of the domain.
	// This is the initial phase of the domain.
	DomainPhasePending = "Pending"
	DomainPhaseActive  = "Active"
	DomainPhaseError   = "Errored"
)

type DomainStatus struct {
	// Phase of the domain.
	Phase DomainPhase `json:"phase,omitempty"`

	// Conditions recorded for the domain.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
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

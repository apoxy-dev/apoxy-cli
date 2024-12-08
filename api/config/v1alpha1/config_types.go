package v1alpha1

import (
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientcmdv1 "k8s.io/client-go/tools/clientcmd/api/v1"
)

var _ runtime.Object = (*Config)(nil)

// +kubebuilder:object:root=true

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Config is the Schema for the Apoxy Backplane configuration.
type Config struct {
	metav1.TypeMeta `json:",inline"`
	// The project ID to use for authentication.
	ProjectID uuid.UUID `json:"projectID,omitempty"`
	// Whether to enable verbose logging.
	Verbose bool `json:"verbose,omitempty"`
	// The URL for the dashboard UI.
	DashboardURL string `json:"dashboardURL,omitempty"`
	// Servers is a map of referencable names to API server configs.
	Servers []NamedServer `json:"servers"`
	// Users is a map of referencable names to user configs.
	Users []clientcmdv1.NamedAuthInfo `json:"users"`
	// Contexts is a map of referencable names to context configs.
	Contexts []NamedContext `json:"contexts"`
	// Resources is a list of resources that this instance should manage/reconcile.
	Resources []ObjectReferenceWithContext `json:"resources"`
}

// NamedServer relates nicknames to API server information.
type NamedServer struct {
	// Name is the nickname for this server.
	Name string `json:"name"`
	// Server is the API server information.
	Server Server `json:"server"`
}

// Server is an API server.
type Server struct {
	clientcmdv1.Cluster `json:",inline"`
	// The host header to set for requests.
	Host string `yaml:"host,omitempty"`
}

// NamedContext relates nicknames to context information.
type NamedContext struct {
	// Name is the nickname for this context.
	Name string `json:"name"`
	// Context is the context information.
	Context Context `json:"context"`
}

// Context is a context for an API server.
type Context struct {
	// Server is the name of the server for this context.
	Server string `json:"server"`
	// User is the name of the authInfo for this context.
	User string `json:"user"`
	// Namespace is the default namespace to use on unspecified requests.
	Namespace string `json:"namespace,omitempty"`
}

// ObjectReferenceWithContext is a reference to an object with an API server context.
type ObjectReferenceWithContext struct {
	corev1.ObjectReference `json:",inline"`
	// Context is the context to use for the resource.
	Context string `json:"context"`
}

package v1alpha1

import (
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var _ runtime.Object = (*Config)(nil)

// +kubebuilder:object:root=true

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Config is the Schema for the Apoxy Backplane configuration.
type Config struct {
	metav1.TypeMeta `json:",inline"`
	// The name of this instance, if not specified the hostname of the machine
	// will be used.
	Name string `json:"name,omitempty"`
	// Whether to enable verbose logging.
	Verbose bool `json:"verbose,omitempty"`
	// The URL for the dashboard UI.
	DashboardURL string `json:"dashboardURL,omitempty"`
	// CurrentProject is the default project ID to use unless overridden.
	CurrentProject uuid.UUID `json:"currentProject,omitempty"`
	// Projects is a list of projects that this instance is managing.
	Projects []Project `json:"projects,omitempty"`
	// Resources is a list of resources that this instance should manage/reconcile.
	Resources []ObjectReferenceWithProject `json:"resources,omitempty"`
}

// Project is a configuration for a project.
type Project struct {
	// ID is the project ID.
	ID uuid.UUID `json:"id"`
	// The base URL for API requests.
	APIBaseURL string `json:"apiBaseURL,omitempty"`
	// The host header to set for API requests.
	APIBaseHost string `json:"apiBaseHost,omitempty"`
	// APIKey is the API key for the project.
	APIKey string `json:"apiKey"`
}

// ObjectReferenceWithContext is a reference to an object with an API server context.
type ObjectReferenceWithProject struct {
	corev1.ObjectReference `json:",inline"`
	// Project is the project ID to use for this object.
	Project string `json:"project"`
}

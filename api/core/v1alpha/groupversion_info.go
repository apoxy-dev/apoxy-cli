package v1alpha

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is group version used to register these objects
	GroupVersion = schema.GroupVersion{Group: "core.apoxy.dev", Version: "v1alpha"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	Scheme = runtime.NewScheme()
)

var AddToScheme = func(s *runtime.Scheme) error {
	metav1.AddToGroupVersion(s, GroupVersion)
	s.AddKnownTypes(GroupVersion,
		&Proxy{},
		&ProxyList{},
		&Address{},
		&AddressList{},
		&Domain{},
		&DomainList{},
	)
	return nil
}

func init() {
	utilruntime.Must(AddToScheme(Scheme))
}

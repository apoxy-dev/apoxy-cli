// Code generated by informer-gen. DO NOT EDIT.

package informers

import (
	"fmt"

	v1alpha1 "github.com/apoxy-dev/apoxy-cli/api/controllers/v1alpha1"
	v1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	policyv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/policy/v1alpha1"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	cache "k8s.io/client-go/tools/cache"
)

// GenericInformer is type of SharedIndexInformer which will locate and delegate to other
// sharedInformers based on type
type GenericInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() cache.GenericLister
}

type genericInformer struct {
	informer cache.SharedIndexInformer
	resource schema.GroupResource
}

// Informer returns the SharedIndexInformer.
func (f *genericInformer) Informer() cache.SharedIndexInformer {
	return f.informer
}

// Lister returns the GenericLister.
func (f *genericInformer) Lister() cache.GenericLister {
	return cache.NewGenericLister(f.Informer().GetIndexer(), f.resource)
}

// ForResource gives generic access to a shared informer of the matching type
// TODO extend this to unknown resources with a client pool
func (f *sharedInformerFactory) ForResource(resource schema.GroupVersionResource) (GenericInformer, error) {
	switch resource {
	// Group=controllers.apoxy.dev, Version=v1alpha1
	case v1alpha1.SchemeGroupVersion.WithResource("proxies"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Controllers().V1alpha1().Proxies().Informer()}, nil

		// Group=core.apoxy.dev, Version=v1alpha
	case v1alpha.SchemeGroupVersion.WithResource("addresses"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Core().V1alpha().Addresses().Informer()}, nil
	case v1alpha.SchemeGroupVersion.WithResource("domains"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Core().V1alpha().Domains().Informer()}, nil
	case v1alpha.SchemeGroupVersion.WithResource("proxies"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Core().V1alpha().Proxies().Informer()}, nil
	case v1alpha.SchemeGroupVersion.WithResource("tunnelnodes"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Core().V1alpha().TunnelNodes().Informer()}, nil

		// Group=policy.apoxy.dev, Version=v1alpha1
	case policyv1alpha1.SchemeGroupVersion.WithResource("ratelimits"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Policy().V1alpha1().RateLimits().Informer()}, nil

	}

	return nil, fmt.Errorf("no informer found for %v", resource)
}
